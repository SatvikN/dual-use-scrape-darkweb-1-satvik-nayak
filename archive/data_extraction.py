# Environemnt setup
# - pip install beautifulsoup4 lxml phonenumbers idna email-validator

import re
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import PhoneNumberMatcher, PhoneNumberFormat
import idna
try:
    from email_validator import validate_email, EmailNotValidError
    HAVE_EMAIL_VALIDATOR = True
except Exception:
    HAVE_EMAIL_VALIDATOR = False

EMAIL_REGEX = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,63}\b'
)

# For obfuscated emails like "name [at] example [dot] com" or "name(at)example(dot)com"
def deobfuscate_emailish(text: str) -> str:
    t = text
    # normalize whitespace
    t = re.sub(r'\s+', ' ', t)
    # replace common "at" tokens with "@"
    t = re.sub(r'(?i)\s*(?:\(|\[|\{)?\s*at\s*(?:\)|\]|\})?\s*', '@', t)
    t = t.replace(' [@] ', '@').replace(' (at) ', '@').replace('[@]', '@')
    # replace common "dot" tokens with "."
    t = re.sub(r'(?i)\s*(?:\(|\[|\{)?\s*dot\s*(?:\)|\]|\})?\s*', '.', t)
    # replace obfuscated separators
    t = t.replace(' (.) ', '.').replace(' [.] ', '.')
    # occasionally people use " d0t " with zero
    t = re.sub(r'(?i)\bd0t\b', '.', t)
    return t

# Extract visible text from HTML (basic)
def visible_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html, 'lxml')
    for t in soup(['script', 'style', 'noscript']):
        t.extract()
    return soup.get_text(' ', strip=True), soup

def normalize_email(addr: str) -> str | None:
    addr = addr.strip()
    # Some sites provide "mailto:addr?subject=..." — split that
    if addr.lower().startswith('mailto:'):
        addr = addr.split(':', 1)[1]
    addr = addr.split('?', 1)[0]
    # Strip surrounding angle brackets
    addr = addr.strip('<>,"\'()[]')
    # Validate and handle IDN domains
    try:
        local, domain = addr.rsplit('@', 1)
    except ValueError:
        return None
    # Lowercase domain, keep local-case as-is (local-part is case-sensitive by spec)
    domain = domain.strip().strip('.').lower()
    # Convert punycode to unicode for readability (optional)
    try:
        if domain.startswith('xn--') or '.xn--' in domain:
            domain = idna.decode(domain)
    except Exception:
        # If IDNA fails, keep as-is
        pass
    candidate = f'{local}@{domain}'
    if HAVE_EMAIL_VALIDATOR:
        try:
            v = validate_email(candidate, allow_smtputf8=True)
            return v.normalized  # normalized includes IDNA-safe domain
        except EmailNotValidError:
            return None
    # Fallback light validation
    if re.match(EMAIL_REGEX, candidate):
        return candidate
    return None

def extract_emails(text: str, soup: BeautifulSoup | None = None) -> set[str]:
    results = set()
    # 1) From mailto: links
    if soup:
        for a in soup.select('a[href^="mailto:"]'):
            norm = normalize_email(a.get('href', ''))
            if norm:
                results.add(norm)
    # 2) From visible text (with deobfuscation)
    t = deobfuscate_emailish(text)
    for m in EMAIL_REGEX.finditer(t):
        norm = normalize_email(m.group(0))
        if norm:
            results.add(norm)
    return results

# Social usernames:
# - From links (high precision)
SOCIAL_PATTERNS = [
    # domain, compiled regex capturing group for username, optional constraints
    ('twitter/x', re.compile(r'https?://(?:www\.)?(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})(?:[/?#]|$)')),
    ('instagram', re.compile(r'https?://(?:www\.)?instagram\.com/([A-Za-z0-9._]{1,30})(?:[/?#]|$)')),
    ('github', re.compile(r'https?://(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})(?:[/?#]|$)')),
    ('reddit', re.compile(r'https?://(?:www\.)?reddit\.com/user/([A-Za-z0-9_-]{3,20})(?:[/?#]|$)')),
    ('telegram', re.compile(r'https?://(?:t\.me|telegram\.me)/([A-Za-z0-9_]{5,32})(?:[/?#]|$)')),
    # Mastodon-like: https://instance.tld/@user
    ('mastodon', re.compile(r'https?://[^/\s]+/@([A-Za-z0-9_\.]{1,30})(?:[/?#]|$)')),
]

# - From @handles in text (exclude overlaps with emails)
HANDLE_REGEX = re.compile(r'(?<!\w)@([A-Za-z0-9_\.]{2,30})(?!\w)')

def extract_usernames(text: str, soup: BeautifulSoup | None = None, email_spans: list[tuple[int,int]] = None) -> set[str]:
    results = set()
    # 1) From social links
    if soup:
        for a in soup.find_all('a', href=True):
            href = a['href']
            for _, rx in SOCIAL_PATTERNS:
                m = rx.search(href)
                if m:
                    results.add(m.group(1))
    # 2) From @handles in text (avoid emails)
    # Build a mask of email spans to avoid false positives
    mask = [False] * len(text)
    if email_spans:
        for s, e in email_spans:
            for i in range(max(0, s), min(len(text), e)):
                mask[i] = True
    for m in HANDLE_REGEX.finditer(text):
        s, e = m.span()
        if any(mask[i] for i in range(s, e)):
            continue  # inside an email
        handle = m.group(1)
        # Light filter: ignore if looks like a domain (@something.tld) immediately followed by dot+tld
        following = text[e:e+10]
        if re.match(r'^\.[A-Za-z]{2,10}\b', following):
            continue
        results.add(handle)
    return results

def extract_phone_numbers(text: str, soup: BeautifulSoup | None = None, default_region: str | None = 'US') -> set[str]:
    results = set()
    # 1) tel: links
    if soup:
        for a in soup.select('a[href^="tel:"]'):
            raw = a.get('href', '')[4:]
            try:
                num = phonenumbers.parse(raw, default_region)
                if phonenumbers.is_possible_number(num) and phonenumbers.is_valid_number(num):
                    results.add(phonenumbers.format_number(num, PhoneNumberFormat.E164))
            except Exception:
                pass
    # 2) From visible text (PhoneNumberMatcher handles punctuation/spacing)
    for match in PhoneNumberMatcher(text, default_region or None):
        num = match.number
        if phonenumbers.is_possible_number(num) and phonenumbers.is_valid_number(num):
            results.add(phonenumbers.format_number(num, PhoneNumberFormat.E164))
    return results

def extract_all(html: str, default_region: str | None = 'US') -> dict:
    text, soup = visible_text_from_html(html)
    # Email spans for avoiding @handle overlap
    t_deob = deobfuscate_emailish(text)
    email_spans = [m.span() for m in EMAIL_REGEX.finditer(t_deob)]
    emails = extract_emails(text, soup)
    usernames = extract_usernames(text, soup, email_spans)
    phones = extract_phone_numbers(text, soup, default_region)
    return {
        'emails': sorted(emails),
        'usernames': sorted(usernames),
        'phone_numbers': sorted(phones),
    }

# Example usage:
# html = "<html>...</html>"
# data = extract_all(html, default_region='US')
# print(data)

# Modified code:
import requests
TOR_SOCKS = "socks5h://127.0.0.1:9150"  # use 9150 if Tor Browser
proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
headers = {"User-Agent": "Mozilla/5.0"}
urls = ["http://g7ejphhubv5idbbu3hb3wawrs5adw7tkx7yjabnf65xtzztgg4hcsqqd.onion/", "http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/"]

for url in urls:
    resp = requests.get(url, proxies=proxies, headers=headers, timeout=60)
    resp.raise_for_status()
    html = resp.text
    data = extract_all(html, default_region=None)
    print(url)
    print(data)

'''
Notes and tuning
- Emails:
  - The regex is intentionally practical (not a full RFC parser). email-validator tightens correctness.
  - The deobfuscator catches common “at/dot” tricks; you can add more (e.g., [d0t], (•), “(underscore)”).
  - De-duplicate by lowercasing the domain part only. The code already normalizes domains.
- Usernames:
  - Social link extraction is most reliable. Extend SOCIAL_PATTERNS for sites you care about.
  - @handle extraction can yield false positives in prose; you can require surrounding whitespace or punctuation and a min length (already 2).
  - To avoid capturing @news in email-like constructs, the code masks email spans first.
- Phone numbers:
  - libphonenumber validates and normalizes to E.164. Set default_region to the country you expect (e.g., 'GB', 'DE'). If truly global, you can try default_region=None but results may be fewer without a leading +.
  - You can also return national/international formats by changing PhoneNumberFormat.
- From links:
  - The code also pulls mailto:/tel: from anchors, which many sites use.

Quality tips
- Start with links, then text: mailto:/tel:/social links are clean signals.
- Validate and normalize:
  - Emails: validate_email for correctness; keep local-part case, lowercase domain; convert IDN punycode if desired.
  - Phones: use libphonenumber; output E.164.
- Reduce false positives:
  - Mask email spans before scanning @handles.
  - Limit handle length and allowed chars.
  - For phones, rely on libphonenumber instead of broad regexes.
- Internationalization:
  - For phones, set default_region appropriately or try None for only +country numbers.
  - For emails, allow IDN domains via email-validator or idna.
- Ethics/legal: respect site terms and laws; don’t collect personal data without consent or legitimate purpose.
'''