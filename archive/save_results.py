'''Python: write gzipped JSONL (streaming, rotates by size)'''
import os, json, gzip, hashlib, socket
from urllib.parse import urlparse
from datetime import datetime, timezone

def make_record(url, title, status_code, extracted, filter_match, match_score, html, crawl_id=None):
    h = hashlib.sha256(html.encode('utf-8', errors='ignore')).hexdigest()
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
        "title": title,
        "filter_match": bool(filter_match),
        "match_score": float(match_score) if match_score is not None else None,
        "emails": sorted(set(extracted.get("emails", []))),
        "usernames": sorted(set(extracted.get("usernames", []))),
        "phone_numbers": sorted(set(extracted.get("phone_numbers", []))),
        "content_sha256": h,
        "producer": socket.gethostname(),
    }

class JsonlSink:
    def __init__(self, out_dir="out", max_bytes=128*1024*1024):
        os.makedirs(out_dir, exist_ok=True)
        self.out_dir = out_dir
        self.max_bytes = max_bytes
        self.part = 0
        self._open_new()

    def _open_new(self):
        if hasattr(self, "fh"): self.fh.close()
        self.part += 1
        path = os.path.join(self.out_dir, f"part-{self.part:05d}.jsonl.gz")
        self.fh = gzip.open(path, "at", encoding="utf-8")
        self.written = 0

    def write(self, rec: dict):
        if self.fh.closed:
            self._open_new()
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        self.fh.write(line)
        self.written += len(line.encode("utf-8"))
        if self.written >= self.max_bytes:
            self._open_new()

    def close(self):
        if self.fh: self.fh.close()

# Usage:
# sink = JsonlSink(out_dir="data/2025-09-02")
# rec = make_record(url, title, status, extracted, filter_match, score, html)
# sink.write(rec)
# sink.close()

# Modified code:
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
sink = JsonlSink(out_dir="data/2025-09-02")

from data_extraction import extract_all
from content_filtering import RuleSet, fetch, extract_text

TOR_SOCKS = "socks5h://127.0.0.1:9150"  # use 9150 if Tor Browser
proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
headers = {"User-Agent": "Mozilla/5.0"}
urls = ["http://g7ejphhubv5idbbu3hb3wawrs5adw7tkx7yjabnf65xtzztgg4hcsqqd.onion/", "http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/"]

rules = RuleSet(
    all_of=["price", "hack", "security"],     # must include both phrases
    any_of=["$", "spdx"],       # at least one of these
    # none_of=["job posting", "hiring"],  # exclude noise
    # regexes=[r"\bCVE-\d{4}-\d{4,7}\b"]  # and must contain a CVE pattern
)

for url in urls:
    html = fetch(url, use_tor=True)
    title, text = extract_text(html)
    status = 200
    extracted = extract_all(html, default_region=None)
    filter_match = rules.match(title, text)
    score = 100.0

    # Parse with lxml parser for speed/robustness
    soup = BeautifulSoup(html, "lxml")

    # Examples: extract title, all links, and text
    title = soup.title.string.strip() if soup.title else ""
    links = [urljoin(url, a.get("href")) for a in soup.select("a[href]")]
    main_text = soup.get_text(" ", strip=True)

    rec = make_record(url, title, status, extracted, filter_match, score, html)
    print(rec)
    # print(sink.fh)
    sink.write(rec)
    sink.close()

'''Python: write Parquet with partitioning (fast analytics)
pip install pyarrow pandas'''
# import pyarrow as pa, pyarrow.parquet as pq, pandas as pd, os
# from datetime import datetime

# def to_parquet(records, base_dir="parquet"):
#     df = pd.DataFrame(records)
#     # Ensure list-typed columns exist
#     for col in ["emails", "usernames", "phone_numbers"]:
#         df[col] = df[col].apply(lambda x: x if isinstance(x, list) else [])
#     # Partition by date (crawl_id) for scalable layout
#     table = pa.Table.from_pandas(df, preserve_index=False)
#     out = os.path.join(base_dir)
#     pq.write_to_dataset(
#         table,
#         root_path=out,
#         partition_cols=["crawl_id"],  # results in crawl_id=YYYY-MM-DD/...
#         compression="zstd"
#     )