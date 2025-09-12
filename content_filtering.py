# Approach
# 1) Fetch HTML (through Tor if needed).
# 2) Extract readable text (strip scripts, styles, nav/boilerplate).
# 3) Normalize text (lowercase, Unicode normalize).
# 4) Apply matching rules:
#    - Simple: keywords/phrases (case-insensitive)
#    - Boolean logic: ALL (AND), ANY (OR), NOT (exclude)
#    - Regex for patterns
#    - Optional: fuzzy matching, proximity, weights
# 5) Return match result and optionally highlight or score.

# Environemnt setup
# - pip install requests[socks] beautifulsoup4 lxml readability-lxml rapidfuzz

import re
import unicodedata
import requests
from bs4 import BeautifulSoup
try:
    from readability import Document  # optional, improves text extraction
    HAVE_READABILITY = True
except Exception:
    HAVE_READABILITY = False

TOR_SOCKS = "socks5h://127.0.0.1:9050"  # use 9150 if using Tor Browser
PROXIES = {"http": TOR_SOCKS, "https": TOR_SOCKS}

def fetch(url, use_tor=False, timeout=60):
    kwargs = {"timeout": timeout, "headers": {"User-Agent": "Mozilla/5.0"}}
    if use_tor:
        kwargs["proxies"] = PROXIES
    r = requests.get(url, **kwargs)
    r.raise_for_status()
    return r.text

def extract_text(html, base_url=None):
    # Try readability to grab main content; fall back to soup.get_text
    if HAVE_READABILITY:
        try:
            doc = Document(html)
            cleaned_html = doc.summary(html_partial=True)
            title = (doc.short_title() or "").strip()
            soup = BeautifulSoup(cleaned_html, "lxml")
            body_text = soup.get_text(" ", strip=True)
            return title, body_text
        except Exception:
            pass
    soup = BeautifulSoup(html, "lxml")
    for t in soup(["script", "style", "noscript"]):
        t.extract()
    title = (soup.title.string.strip() if soup.title and soup.title.string else "")
    body_text = soup.get_text(" ", strip=True)
    return title, body_text

def normalize(text):
    return unicodedata.normalize("NFKC", text).casefold()

class RuleSet:
    def __init__(self, all_of=None, any_of=None, none_of=None, regexes=None):
        # strings or phrases; regexes are compiled
        self.all_of = [normalize(x) for x in (all_of or [])]
        self.any_of = [normalize(x) for x in (any_of or [])]
        self.none_of = [normalize(x) for x in (none_of or [])]
        self.regexes = [re.compile(rx, re.I) for rx in (regexes or [])]

    def match(self, title, body):
        text_norm = normalize(title + " " + body)
        # Boolean string checks
        if self.all_of and not all(k in text_norm for k in self.all_of):
            return False
        if self.any_of and not any(k in text_norm for k in self.any_of):
            return False
        if self.none_of and any(k in text_norm for k in self.none_of):
            return False
        # Regex checks
        for rx in self.regexes:
            if not rx.search(title) and not rx.search(body):
                return False
        return True

# Example usage:
# rules = RuleSet(
#     all_of=["supply chain", "sbom"],     # must include both phrases
#     any_of=["cyclonedx", "spdx"],       # at least one of these
#     none_of=["job posting", "hiring"],  # exclude noise
#     regexes=[r"\bCVE-\d{4}-\d{4,7}\b"]  # and must contain a CVE pattern
# )
rules = RuleSet(
    all_of=["price", "hack", "security"],     # must include both phrases
    any_of=["$", "spdx"],       # at least one of these
    # none_of=["job posting", "hiring"],  # exclude noise
    # regexes=[r"\bCVE-\d{4}-\d{4,7}\b"]  # and must contain a CVE pattern
)

urls = ["http://g7ejphhubv5idbbu3hb3wawrs5adw7tkx7yjabnf65xtzztgg4hcsqqd.onion/", "http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/"]

for url in urls:
    html = fetch(url, use_tor=True)
    title, text = extract_text(html)
    print(title)
    # print(text)
    print(rules.match(title, text))

# Optional: scoring and fuzzy matching
# - Weighted scoring: assign points per hit and accept if score >= threshold.
# - Fuzzy matching (handles typos/variants): use rapidfuzz.
# Example snippet:
# from rapidfuzz import fuzz
# def fuzzy_any(text, terms, min_ratio=85):
#     t = normalize(text)
#     for term in terms:
#         if fuzz.partial_ratio(normalize(term), t) >= min_ratio:
#             return True
#     return False
# Use inside RuleSet.match to complement exact checks.

# Optional: proximity/co-occurrence
# - To reduce false positives, require two keywords to appear within N words of each other. Tokenize text_norm.split() and slide a window to check proximity.