import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

TOR_SOCKS = "socks5h://127.0.0.1:9050"  # use 9150 if Tor Browser
proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
headers = {"User-Agent": "Mozilla/5.0"}

urls = ["http://g7ejphhubv5idbbu3hb3wawrs5adw7tkx7yjabnf65xtzztgg4hcsqqd.onion/", "http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/"]

for url in urls:
    resp = requests.get(url, proxies=proxies, headers=headers, timeout=60)
    resp.raise_for_status()

    # Parse with lxml parser for speed/robustness
    soup = BeautifulSoup(resp.text, "lxml")

    # Examples: extract title, all links, and text
    title = soup.title.string.strip() if soup.title else ""
    links = [urljoin(url, a.get("href")) for a in soup.select("a[href]")]
    main_text = soup.get_text(" ", strip=True)

    print("Title:", title)
    print("Links:", links[:10])
    print("Text sample:", main_text[:300])
    print()