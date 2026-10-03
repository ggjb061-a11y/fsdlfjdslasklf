"""
Additional subdomain-discovery sources (all free, no API key required
unless noted). Each module exports a `fetch(domain) -> set[str]` function.

Sources:
  * alienvault     - AlienVault OTX passive DNS
  * threatcrowd    - ThreatCrowd DNS (requires UA)
  * rapiddns       - rapiddns.io subdomain scraping
  * hackertarget   - hackertarget hostsearch endpoint
  * urlscan        - URLScan.io public search API
  * bufferover     - dns.bufferover.run (TLS cert PDNS)
  * commoncrawl    - CommonCrawl index API
  * certspotter    - certspotter.com free CT log endpoint
  * tls_san        - connect to the apex IP on 443, enumerate SAN names
  * js_mining      - extract subdomains from downloaded JS files
"""
from .alienvault import fetch as fetch_alienvault
from .threatcrowd import fetch as fetch_threatcrowd
from .rapiddns import fetch as fetch_rapiddns
from .hackertarget_hostsearch import fetch as fetch_hackertarget_hostsearch
from .urlscan import fetch as fetch_urlscan
from .bufferover import fetch as fetch_bufferover
from .commoncrawl import fetch as fetch_commoncrawl
from .certspotter import fetch as fetch_certspotter
from .tls_san import fetch as fetch_tls_san
from .js_mining import fetch as fetch_js_mining


ALL_SOURCES = [
    ("AlienVault OTX",      fetch_alienvault),
    ("ThreatCrowd",         fetch_threatcrowd),
    ("RapidDNS",            fetch_rapiddns),
    ("HackerTarget hostsearch", fetch_hackertarget_hostsearch),
    ("URLScan.io",          fetch_urlscan),
    ("BufferOver dns",      fetch_bufferover),
    ("CommonCrawl index",   fetch_commoncrawl),
    ("CertSpotter",         fetch_certspotter),
]

__all__ = [
    "ALL_SOURCES",
    "fetch_alienvault", "fetch_threatcrowd", "fetch_rapiddns",
    "fetch_hackertarget_hostsearch", "fetch_urlscan", "fetch_bufferover",
    "fetch_commoncrawl", "fetch_certspotter", "fetch_tls_san", "fetch_js_mining",
]
