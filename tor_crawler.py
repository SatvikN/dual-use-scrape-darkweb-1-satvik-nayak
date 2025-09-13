'''Below is a single, complete Python script that integrates:
- Tor access (SOCKS5 “socks5h”) for .onion and clearnet
- HTML fetching and parsing
- Content filtering (keywords/regex, AND/OR/NOT)
- Data extraction (emails, usernames, phone numbers)
- Result saving to gzipped JSON Lines with size-based rotation
- Optional Parquet export (via PyArrow) after the run

It’s intentionally privacy-friendly (no cookies, no referer, per-domain Tor circuit isolation optional).

How to run (quick)
1) Install dependencies:
   pip install requests[socks] beautifulsoup4 lxml readability-lxml phonenumbers idna email-validator pyarrow pandas

2) Save the script below as tor_crawler.py.

3) Prepare a URL list file (one per line), e.g., urls.txt.

4) Optional filter rules JSON (rules.json), example:
   {
     "all_of": ["supply chain", "sbom"],
     "any_of": ["spdx", "cyclonedx"],
     "none_of": ["hiring", "job posting"],
     "regexes": ["\\bCVE-\\d{4}-\\d{4,7}\\b"]
   }

5) Run:
    python tor_crawler.py --urls urls.txt --use-tor --tor-port 9150 --tor-isolate-by-domain --rules rules.json --out-dir out --default-region US --delay-min 1.0 --delay-max 3.0 --parquet parquet_out
    
Notes and options
- Tor usage:
  - Ensure Tor is running. Defaults assume a Tor daemon on 127.0.0.1:9050. If using Tor Browser, use --tor-port 9150.
  - --tor-isolate-by-domain leverages Tor’s IsolateSOCKSAuth: the script sets the SOCKS username to the domain so circuits are separated per site.

- Filtering:
  - Place keyword rules in a JSON file and point --rules to it.
  - Regex strings must be valid Python regexes. They must all match somewhere in title OR body to pass.

- Output:
  - Gzipped JSONL parts in --out-dir (rotated by size). Each record has emails, usernames, phone_numbers, title, status, etc.
  - Optional Parquet dataset with partitioning by crawl_id (pass --parquet parquet_out).

- Privacy and safety:
  - The script uses socks5h to avoid DNS leaks and sets a Tor Browser-like UA. It does not store cookies or referrers.
  - Keep concurrency low (this script is sequential). If you add threads/async, limit to 1–3 with Tor.'''

# Script: tor_crawler.py
#!/usr/bin/env python3
# Integrated Tor-aware fetch + parse + filter + extract + save pipeline.
# Dependencies:
#   pip install requests[socks] beautifulsoup4 lxml readability-lxml phonenumbers idna email-validator pyarrow pandas
# Notes:
# - Use socks5h to resolve hostnames through Tor (.onion and DNS leak protection).
# - Keep concurrency low with Tor. This script runs sequentially by default.
# - For stronger anonymity, run inside Tails/Whonix and keep defaults conservative.

import argparse
import gzip
import hashlib
import json
import os
import random
import re
import socket
import sys
import time
import unicodedata
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict
from urllib.parse import urlparse, urlsplit

import requests
from bs4 import BeautifulSoup

# Optional HTML main-content extraction
try:
    from readability import Document
    HAVE_READABILITY = True
except Exception:
    HAVE_READABILITY = False

# Phone and email helpers
import phonenumbers
from phonenumbers import PhoneNumberMatcher, PhoneNumberFormat
import idna
try:
    from email_validator import validate_email, EmailNotValidError
    HAVE_EMAIL_VALIDATOR = True
except Exception:
    HAVE_EMAIL_VALIDATOR = False

# ----------------------------
# Filtering
# ----------------------------
class RuleSet:
    def __init__(self, all_of=None, any_of=None, none_of=None, regexes=None):
        self.all_of = [self._norm(x) for x in (all_of or [])]
        self.any_of = [self._norm(x) for x in (any_of or [])]
        self.none_of = [self._norm(x) for x in (none_of or [])]
        self.regexes = [re.compile(rx, re.I) for rx in (regexes or [])]

    @staticmethod
    def _norm(s: str) -> str:
        return unicodedata.normalize("NFKC", s).casefold()

    def match(self, title: str, body: str) -> bool:
        text_norm = self._norm((title or "") + " " + (body or ""))
        if self.all_of and not all(k in text_norm for k in self.all_of):
            return False
        if self.any_of and not any(k in text_norm for k in self.any_of):
            return False
        if self.none_of and any(k in text_norm for k in self.none_of):
            return False
        # Regexes must all match somewhere in title or body
        for rx in self.regexes:
            if not (rx.search(title or "") or rx.search(body or "")):
                return False
        return True

# ----------------------------
# Extraction
# ----------------------------
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,63}\b')

SOCIAL_PATTERNS = [
    ('twitter/x', re.compile(r'https?://(?:www\.)?(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})(?:[/?#]|$)')),
    ('instagram', re.compile(r'https?://(?:www\.)?instagram\.com/([A-Za-z0-9._]{1,30})(?:[/?#]|$)')),
    ('github', re.compile(r'https?://(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})(?:[/?#]|$)')),
    ('reddit', re.compile(r'https?://(?:www\.)?reddit\.com/user/([A-Za-z0-9_-]{3,20})(?:[/?#]|$)')),
    ('telegram', re.compile(r'https?://(?:t\.me|telegram\.me)/([A-Za-z0-9_]{5,32})(?:[/?#]|$)')),
    ('mastodon', re.compile(r'https?://[^/\s]+/@([A-Za-z0-9_\.]{1,30})(?:[/?#]|$)')),
]

HANDLE_REGEX = re.compile(r'(?<!\w)@([A-Za-z0-9_\.]{2,30})(?!\w)')

def deobfuscate_emailish(text: str) -> str:
    t = re.sub(r'\s+', ' ', text)
    t = re.sub(r'(?i)\s*(?:\(|\[|\{)?\s*at\s*(?:\)|\]|\})?\s*', '@', t)
    t = t.replace(' [@] ', '@').replace(' (at) ', '@').replace('[@]', '@')
    t = re.sub(r'(?i)\s*(?:\(|\[|\{)?\s*dot\s*(?:\)|\]|\})?\s*', '.', t)
    t = t.replace(' (.) ', '.').replace(' [.] ', '.')
    t = re.sub(r'(?i)\bd0t\b', '.', t)
    return t

def visible_text_from_html(html: str) -> Tuple[str, BeautifulSoup]:
    soup = BeautifulSoup(html, 'lxml')
    for t in soup(['script', 'style', 'noscript']):
        t.extract()
    return soup.get_text(' ', strip=True), soup

def normalize_email(addr: str) -> Optional[str]:
    addr = addr.strip()
    if addr.lower().startswith('mailto:'):
        addr = addr.split(':', 1)[1]
    addr = addr.split('?', 1)[0]
    addr = addr.strip('<>,"\'()[]')
    try:
        local, domain = addr.rsplit('@', 1)
    except ValueError:
        return None
    domain = domain.strip().strip('.').lower()
    try:
        if domain.startswith('xn--') or '.xn--' in domain:
            domain = idna.decode(domain)
    except Exception:
        pass
    candidate = f'{local}@{domain}'
    if HAVE_EMAIL_VALIDATOR:
        try:
            v = validate_email(candidate, allow_smtputf8=True)
            return v.normalized
        except EmailNotValidError:
            return None
    if re.match(EMAIL_REGEX, candidate):
        return candidate
    return None

def extract_emails(text: str, soup: Optional[BeautifulSoup]) -> List[str]:
    results = set()
    if soup:
        for a in soup.select('a[href^="mailto:"]'):
            norm = normalize_email(a.get('href', ''))
            if norm:
                results.add(norm)
    t = deobfuscate_emailish(text)
    for m in EMAIL_REGEX.finditer(t):
        norm = normalize_email(m.group(0))
        if norm:
            results.add(norm)
    return sorted(results)

def extract_usernames(text: str, soup: Optional[BeautifulSoup], email_spans: List[Tuple[int,int]]) -> List[str]:
    results = set()
    if soup:
        for a in soup.find_all('a', href=True):
            href = a['href']
            for _, rx in SOCIAL_PATTERNS:
                m = rx.search(href)
                if m:
                    results.add(m.group(1))
    mask = [False] * len(text)
    for s, e in email_spans:
        for i in range(max(0, s), min(len(text), e)):
            mask[i] = True
    for m in HANDLE_REGEX.finditer(text):
        s, e = m.span()
        if any(mask[i] for i in range(s, e)):
            continue
        handle = m.group(1)
        following = text[e:e+10]
        if re.match(r'^\.[A-Za-z]{2,10}\b', following):
            continue
        results.add(handle)
    return sorted(results)

def extract_phone_numbers(text: str, soup: Optional[BeautifulSoup], default_region: Optional[str]) -> List[str]:
    results = set()
    if soup:
        for a in soup.select('a[href^="tel:"]'):
            raw = a.get('href', '')[4:]
            try:
                num = phonenumbers.parse(raw, default_region)
                if phonenumbers.is_possible_number(num) and phonenumbers.is_valid_number(num):
                    results.add(phonenumbers.format_number(num, PhoneNumberFormat.E164))
            except Exception:
                pass
    for match in PhoneNumberMatcher(text, default_region or None):
        num = match.number
        if phonenumbers.is_possible_number(num) and phonenumbers.is_valid_number(num):
            results.add(phonenumbers.format_number(num, PhoneNumberFormat.E164))
    return sorted(results)

def extract_all(html: str, default_region: Optional[str]) -> Dict[str, List[str]]:
    text, soup = visible_text_from_html(html)
    t_deob = deobfuscate_emailish(text)
    email_spans = [m.span() for m in EMAIL_REGEX.finditer(t_deob)]
    return {
        "emails": extract_emails(text, soup),
        "usernames": extract_usernames(text, soup, email_spans),
        "phone_numbers": extract_phone_numbers(text, soup, default_region),
        "title_text": (BeautifulSoup(html, "lxml").title.string.strip()
                       if BeautifulSoup(html, "lxml").title and BeautifulSoup(html, "lxml").title.string else ""),
        "visible_text": text
    }

# ----------------------------
# Fetching via Tor (or direct)
# ----------------------------
TOR_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"

def build_proxies(use_tor: bool, tor_host: str, tor_port: int, username: Optional[str] = None) -> Optional[dict]:
    if not use_tor:
        return None
    auth = f"{username}@" if username else ""
    proxy = f"socks5h://{auth}{tor_host}:{tor_port}"
    return {"http": proxy, "https": proxy}

def fetch_url(url: str, use_tor: bool, tor_host: str, tor_port: int, isolate_id: Optional[str], timeout: int = 60) -> Tuple[int, str]:
    session = requests.Session()
    session.trust_env = False  # ignore system proxy/certs
    session.headers.update({
        "User-Agent": TOR_BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    })
    proxies = build_proxies(use_tor, tor_host, tor_port, username=isolate_id)
    try:
        resp = session.get(url, proxies=proxies, timeout=timeout, allow_redirects=True)
        return resp.status_code, resp.text if resp.text is not None else ""
    except requests.RequestException as e:
        raise RuntimeError(f"Request failed: {e}") from e

# ----------------------------
# Output sinks
# ----------------------------
class JsonlSink:
    def __init__(self, out_dir="out", max_bytes=128*1024*1024):
        os.makedirs(out_dir, exist_ok=True)
        self.out_dir = out_dir
        self.max_bytes = max_bytes
        self.part = 0
        self.fh = None
        self.written = 0
        self._open_new()

    def _open_new(self):
        if self.fh:
            self.fh.close()
        self.part += 1
        path = os.path.join(self.out_dir, f"part-{self.part:05d}.jsonl.gz")
        self.fh = gzip.open(path, "at", encoding="utf-8")
        self.written = 0

    def write(self, rec: dict):
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        self.fh.write(line)
        self.written += len(line.encode("utf-8"))
        if self.written >= self.max_bytes:
            self._open_new()

    def close(self):
        if self.fh:
            self.fh.close()

def to_parquet(records: List[dict], base_dir: str):
    import pyarrow as pa
    import pyarrow.parquet as pq
    import pandas as pd
    os.makedirs(base_dir, exist_ok=True)
    df = pd.DataFrame(records)
    for col in ["emails", "usernames", "phone_numbers"]:
        if col in df.columns:
            df[col] = df[col].apply(lambda x: x if isinstance(x, list) else [])
        else:
            df[col] = [[] for _ in range(len(df))]
    table = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_to_dataset(table, root_path=base_dir, partition_cols=["crawl_id"], compression="zstd")

# ----------------------------
# Record creation
# ----------------------------
def make_record(url: str, status_code: int, title: str, extracted: dict, filter_match: bool, match_score: Optional[float], html: str, crawl_id: Optional[str]) -> dict:
    h = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    domain = urlparse(url).netloc.lower()
    rid = hashlib.sha256((url + ts).encode()).hexdigest()
    return {
        "id": rid,
        "crawl_id": crawl_id or datetime.now().strftime("%Y-%m-%d"),
        "url": url,
        "domain": domain,
        "fetched_at": ts,
        "status_code": status_code,
        "title": title or extracted.get("title_text", "") or "",
        "filter_match": bool(filter_match),
        "match_score": float(match_score) if match_score is not None else None,
        "emails": sorted(set(extracted.get("emails", []))),
        "usernames": sorted(set(extracted.get("usernames", []))),
        "phone_numbers": sorted(set(extracted.get("phone_numbers", []))),
        "content_sha256": h,
        "producer": socket.gethostname(),
    }

# ----------------------------
# Main crawl loop
# ----------------------------
def load_rules(path: Optional[str]) -> RuleSet:
    if not path:
        return RuleSet()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return RuleSet(
        all_of=data.get("all_of"),
        any_of=data.get("any_of"),
        none_of=data.get("none_of"),
        regexes=data.get("regexes"),
    )

def load_urls(path: str) -> List[str]:
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            urls.append(s)
    return urls

def main():
    ap = argparse.ArgumentParser(description="Tor-aware HTML fetcher + filter + extractor")
    ap.add_argument("--urls", help="Path to file with URLs (one per line)")
    ap.add_argument("--url", help="Single URL (can be repeated)", action="append")
    ap.add_argument("--use-tor", help="Route via Tor SOCKS5 (socks5h)", action="store_true")
    ap.add_argument("--tor-host", default="127.0.0.1", help="Tor SOCKS host (default 127.0.0.1)")
    ap.add_argument("--tor-port", type=int, default=9050, help="Tor SOCKS port (9050 daemon, 9150 Tor Browser)")
    ap.add_argument("--tor-isolate-by-domain", help="Use per-domain SOCKS username to isolate Tor circuits", action="store_true")
    ap.add_argument("--rules", help="Path to JSON rules file (all_of/any_of/none_of/regexes)")
    ap.add_argument("--out-dir", default="out", help="Directory for gzipped JSONL parts")
    ap.add_argument("--rotate-mb", type=int, default=128, help="Rotate JSONL files every N MB")
    ap.add_argument("--default-region", default="US", help="Default phone region (e.g., US, GB, DE) or empty for None")
    ap.add_argument("--crawl-id", help="Crawl/run ID (default YYYY-MM-DD)")
    ap.add_argument("--delay-min", type=float, default=0.5, help="Min delay between requests (seconds)")
    ap.add_argument("--delay-max", type=float, default=2.0, help="Max delay between requests (seconds)")
    ap.add_argument("--parquet", help="Write a Parquet dataset after run to this directory")
    args = ap.parse_args()

    urls = []
    if args.urls:
        urls.extend(load_urls(args.urls))
    if args.url:
        urls.extend(args.url)
    if not urls:
        print("No URLs provided. Use --urls file or --url URL.", file=sys.stderr)
        sys.exit(2)

    rules = load_rules(args.rules)
    default_region = args.default_region if args.default_region else None

    sink = JsonlSink(out_dir=args.out_dir, max_bytes=args.rotate_mb * 1024 * 1024)
    all_records = []  # Only used if --parquet is set

    for idx, url in enumerate(urls, 1):
        parsed = urlsplit(url)
        if not parsed.scheme:
            url = "http://" + url  # allow bare host/.onion lines

        isolate_id = None
        if args.use_tor and args.tor_isolate_by_domain:
            isolate_id = (parsed.netloc or urlparse(url).netloc or "id").lower()

        try:
            status, body = fetch_url(url, args.use_tor, args.tor_host, args.tor_port, isolate_id=isolate_id)
        except Exception as e:
            print(f"[{idx}/{len(urls)}] {url} -> ERROR: {e}", file=sys.stderr)
            continue

        extracted = extract_all(body or "", default_region)
        title = extracted.get("title_text", "")
        vis_text = extracted.get("visible_text", "")

        filter_match = rules.match(title, vis_text)
        match_score = 1.0 if filter_match else 0.0  # placeholder; extend if you implement scoring

        rec = make_record(url, status, title, extracted, filter_match, match_score, body or "", args.crawl_id)
        sink.write(rec)
        if args.parquet:
            all_records.append(rec)

        print(f"[{idx}/{len(urls)}] {url} -> {status} | matched={filter_match} | emails={len(extracted['emails'])} phones={len(extracted['phone_numbers'])} users={len(extracted['usernames'])}", file=sys.stderr)

        # polite randomized delay
        delay = random.uniform(max(0, args.delay_min), max(args.delay_min, args.delay_max))
        time.sleep(delay)

    sink.close()

    if args.parquet:
        to_parquet(all_records, args.parquet)
        print(f"Wrote Parquet dataset to {args.parquet}", file=sys.stderr)

if __name__ == "__main__":
    main()

# To run:
# python tor_crawler.py --urls urls.txt --use-tor --tor-port 9150 --tor-isolate-by-domain --rules rules.json --out-dir out --default-region US --delay-min 1.0 --delay-max 3.0 --parquet parquet_out