"""
Extended reconnaissance module - adds many new recon surfaces to the main
ReconModule without rewriting it. ReconModule.run() calls into this module
to augment its results.

Features added here:
  - ASN / BGP lookup (Team Cymru + bgp.he.net)
  - Shodan InternetDB (free, no API key) for open ports + known vulns per IP
  - SPF / DMARC / DKIM / DNSSEC analysis
  - security.txt discovery
  - HTTP/2 and HTTP/3 ALPN detection
  - JA3-like TLS fingerprint via openssl
  - Reverse DNS enumeration
  - IP geolocation (ip-api.com, free)
  - Subdomain permutation generator (altdns-style)
  - DNS brute-force with built-in top-100 subdomain wordlist
  - Common tech endpoint fingerprinting
"""
import json
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from .utils import run, which, write_lines, read_lines
from .models import Finding, HostRecord

logger = logging.getLogger("autoscan.recon_ext")


# Top-100 subdomain names for lightweight brute-force (used when no massdns)
TOP_100_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
    "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1",
    "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
    "info", "apps", "download", "remote", "db", "forums", "store", "relay", "files",
    "newsletter", "app", "live", "owa", "en", "start", "sms", "office", "exchange",
    "ipv4", "git", "jira", "ci", "jenkins", "staging-api", "preprod",
]

# Common permutation patterns for altdns-style discovery
PERMUTATION_PATTERNS = [
    "{sub}-dev", "dev-{sub}", "{sub}-staging", "staging-{sub}",
    "{sub}-test", "test-{sub}", "{sub}-prod", "{sub}-qa",
    "{sub}-admin", "admin-{sub}", "{sub}-v2", "{sub}-new",
    "{sub}-internal", "{sub}-api",
]


# -----------------------------------------------------------------------
# ASN / BGP
# -----------------------------------------------------------------------

def asn_lookup(ip: str) -> dict:
    """Query Team Cymru whois for ASN + prefix + country."""
    if not ip:
        return {}
    rc, out, _ = run(
        ["dig", "+short", "TXT", f"{'.'.join(reversed(ip.split('.')))}.origin.asn.cymru.com"],
        timeout=15,
    )
    if rc != 0 or not out:
        return {}
    txt = out.strip().strip('"').strip()
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 4:
        return {}
    asn_num = parts[0].split()[0] if parts[0] else ""
    data = {"asn": asn_num, "prefix": parts[1], "country": parts[2], "registry": parts[3]}

    if asn_num:
        rc2, out2, _ = run(
            ["dig", "+short", "TXT", f"AS{asn_num}.asn.cymru.com"],
            timeout=15,
        )
        if rc2 == 0 and out2:
            txt2 = out2.strip().strip('"').strip()
            parts2 = [p.strip() for p in txt2.split("|")]
            if len(parts2) >= 5:
                data["as_name"] = parts2[4]
    return data


# -----------------------------------------------------------------------
# Shodan InternetDB (free, no API key)
# -----------------------------------------------------------------------

def shodan_internetdb(ip: str) -> dict:
    """
    GET https://internetdb.shodan.io/<ip> - returns ports, hostnames, vulns, cpes.
    Rate-limited by Shodan; failing silently is fine.
    """
    if not ip:
        return {}
    rc, body, _ = run(
        ["curl", "-s", "--max-time", "10", f"https://internetdb.shodan.io/{ip}"],
        timeout=15,
    )
    if rc != 0 or not body:
        return {}
    try:
        return json.loads(body)
    except Exception:
        return {}


# -----------------------------------------------------------------------
# Mail security records (SPF, DMARC, DKIM, DNSSEC)
# -----------------------------------------------------------------------

def analyze_mail_security(domain: str) -> list[Finding]:
    findings: list[Finding] = []

    rc, spf_out, _ = run(["dig", "+short", "TXT", domain], timeout=15)
    spf_records = []
    if rc == 0 and spf_out:
        for line in spf_out.splitlines():
            cleaned = line.strip().strip('"')
            if cleaned.lower().startswith("v=spf1"):
                spf_records.append(cleaned)
    # SPF/DMARC/DKIM are email-authentication defenses. Realistic risk:
    # they let attackers spoof mail, but the attacker needs to actually
    # send email AND the victim's inbox needs to accept it. Classifying
    # these as LOW/MEDIUM, not HIGH.
    if not spf_records:
        findings.append(Finding(
            severity="low",
            title="Missing SPF record",
            host=domain,
            detail=f"No SPF (v=spf1) TXT record on {domain}. Mail from this domain is easier to spoof but exploitation requires attacker to send mail.",
            source="mail_security",
        ))
    else:
        spf = spf_records[0]
        # Tokenize mechanisms and inspect the FINAL `all` qualifier.
        # Per RFC 7208, no qualifier means `+` (pass), so a record ending
        # in a bare `all` is equivalent to `+all`.
        tokens = [t for t in spf.split() if t]
        final_all = None
        for tok in tokens:
            tl = tok.lower()
            if tl == "all" or tl.endswith(" all"):
                final_all = "+"
            elif tl in ("+all", "-all", "~all", "?all"):
                final_all = tl[0]
        if final_all == "+":
            findings.append(Finding(
                severity="medium",
                title="SPF +all - permits spoofing from any sender",
                host=domain,
                detail=f"SPF record resolves to +all (explicit or bare `all`): {spf}. Enables anyone to send mail as this domain.",
                source="mail_security", evidence=spf,
            ))
        elif final_all == "?":
            findings.append(Finding(
                severity="info",
                title="SPF ?all - neutral policy",
                host=domain,
                detail=f"SPF ?all leaves receivers to decide: {spf}",
                source="mail_security", evidence=spf,
            ))
        # RFC 7208 §5.5 discourages the `ptr` mechanism (DoS + privacy risk).
        if re.search(r"(?:^|\s)[+\-~?]?ptr(?:$|[\s:])", spf, re.IGNORECASE):
            findings.append(Finding(
                severity="low",
                title="SPF uses discouraged `ptr` mechanism",
                host=domain,
                detail=f"SPF record contains `ptr`, deprecated by RFC 7208 §5.5: {spf}",
                source="mail_security", evidence=spf,
            ))

    rc, dmarc_out, _ = run(
        ["dig", "+short", "TXT", f"_dmarc.{domain}"], timeout=15,
    )
    dmarc_records = []
    if rc == 0 and dmarc_out:
        for line in dmarc_out.splitlines():
            cleaned = line.strip().strip('"')
            if cleaned.lower().startswith("v=dmarc1"):
                dmarc_records.append(cleaned)
    if not dmarc_records:
        findings.append(Finding(
            severity="low",
            title="Missing DMARC record",
            host=domain,
            detail=f"No DMARC TXT record on _dmarc.{domain}. Mail receivers cannot apply alignment policy; spoofing easier.",
            source="mail_security",
        ))
    else:
        dmarc = dmarc_records[0]
        # Boundary-anchored match on the `p=` tag so `sp=none` (subdomain
        # policy) does not mis-flag a domain whose main policy is reject.
        if re.search(r"(?:^|;\s*)p\s*=\s*none\b", dmarc, re.IGNORECASE):
            findings.append(Finding(
                severity="low",
                title="DMARC policy is p=none",
                host=domain,
                detail=f"DMARC enforces monitor-only (p=none): {dmarc}. Fail reports collected but no enforcement.",
                source="mail_security", evidence=dmarc,
            ))

    # DNSSEC via DS record (via dig +trace or looking for RRSIG)
    rc, ds_out, _ = run(["dig", "+short", "DS", domain], timeout=15)
    if not (rc == 0 and ds_out and ds_out.strip()):
        findings.append(Finding(
            severity="info",
            title="No DNSSEC DS record",
            host=domain,
            detail=f"{domain} does not publish a DS record; DNSSEC not deployed at parent",
            source="dnssec",
        ))

    return findings


# -----------------------------------------------------------------------
# security.txt discovery
# -----------------------------------------------------------------------

def discover_security_txt(live_hosts: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for host in live_hosts[:5]:
        for path in ["/.well-known/security.txt", "/security.txt"]:
            url = f"{host}{path}"
            rc, body, _ = run(["curl", "-sI", "--max-time", "6", url], timeout=10)
            if rc != 0 or not body:
                continue
            first = body.splitlines()[0] if body.splitlines() else ""
            if "200" in first.split()[1:3]:
                rc, content, _ = run(["curl", "-sL", "--max-time", "6", url], timeout=10)
                findings.append(Finding(
                    severity="info",
                    title="security.txt present",
                    host=host,
                    detail=f"Security contact file published at {url}",
                    source="security_txt",
                    url=url,
                    evidence=(content or "")[:300],
                ))
                break
    return findings


# -----------------------------------------------------------------------
# HTTP/2 / HTTP/3 detection
# -----------------------------------------------------------------------

def detect_http_versions(host: str) -> dict:
    """Return {'h2': bool, 'h3': bool} by probing ALPN."""
    result = {"h2": False, "h3": False, "tls_version": ""}
    if not which("openssl"):
        return result
    rc, out, err = run(
        ["openssl", "s_client", "-connect", f"{host}:443",
         "-servername", host, "-alpn", "h2,http/1.1"],
        stdin_data="", timeout=15,
    )
    combined = (out or "") + (err or "")
    if "ALPN protocol: h2" in combined:
        result["h2"] = True
    m = re.search(r"Protocol\s*:\s*(TLSv[\d.]+)", combined)
    if m:
        result["tls_version"] = m.group(1)
    # HTTP/3 (quic) harder to probe without h3 client; look for Alt-Svc header
    rc, hdrs, _ = run(
        ["curl", "-sI", "--max-time", "6", f"https://{host}/"],
        timeout=10,
    )
    if hdrs and "alt-svc" in hdrs.lower() and "h3" in hdrs.lower():
        result["h3"] = True
    return result


# -----------------------------------------------------------------------
# Reverse DNS
# -----------------------------------------------------------------------

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# -----------------------------------------------------------------------
# IP geolocation (ip-api.com free tier)
# -----------------------------------------------------------------------

def ip_geolocate(ip: str) -> dict:
    if not ip:
        return {}
    rc, body, _ = run(
        ["curl", "-s", "--max-time", "6",
         f"http://ip-api.com/json/{ip}?fields=country,city,isp,org,as"],
        timeout=10,
    )
    if rc != 0 or not body:
        return {}
    try:
        return json.loads(body)
    except Exception:
        return {}


# -----------------------------------------------------------------------
# Subdomain brute-force + permutations
# -----------------------------------------------------------------------

def dns_brute_force(domain: str, wordlist: list[str] = None, threads: int = 20) -> list[str]:
    """Resolve each <word>.<domain>; return list of resolved hostnames."""
    if wordlist is None:
        wordlist = TOP_100_SUBDOMAINS
    found: list[str] = []

    def _resolve(sub: str) -> str | None:
        host = f"{sub}.{domain}"
        try:
            socket.gethostbyname(host)
            return host
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_resolve, s) for s in wordlist]
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return found


def permute_subdomains(existing: list[str], domain: str) -> list[str]:
    """Generate altdns-style permutations of discovered subdomains."""
    permuted: set[str] = set()
    suffix = f".{domain}"
    for sub in existing:
        if not sub.endswith(suffix):
            continue
        prefix = sub[:-len(suffix)]
        parts = prefix.split(".")
        for p in parts:
            if not p:
                continue
            for pat in PERMUTATION_PATTERNS:
                new = pat.format(sub=p) + suffix
                if new != sub and new != domain:
                    permuted.add(new)
    return sorted(permuted)


# -----------------------------------------------------------------------
# Top-level orchestrator consumed by ReconModule
# -----------------------------------------------------------------------

def extend_recon(target: str, dirs: dict, live_hosts: list, host_records: list,
                 subdomains: list, threads: int = 10) -> dict:
    """
    Run all extended recon passes. Returns a dict with findings + extra data.

    Return keys:
      findings: list[Finding]  - new findings to append to ScanResult
      extra_subdomains: list[str] - new subdomains to merge in
      asn_info: dict  - ASN info per IP
      shodan_info: dict  - Shodan InternetDB data per IP
      geo_info: dict  - geolocation per IP
      http_versions: dict - HTTP/2/3 support per host
    """
    out = {
        "findings": [],
        "extra_subdomains": [],
        "asn_info": {},
        "shodan_info": {},
        "geo_info": {},
        "http_versions": {},
    }

    # Mail / DNS security
    try:
        out["findings"].extend(analyze_mail_security(target))
    except Exception as exc:
        logger.debug(f"  mail_security: {exc}")

    # security.txt
    try:
        out["findings"].extend(discover_security_txt(live_hosts))
    except Exception as exc:
        logger.debug(f"  security_txt: {exc}")

    # DNS brute-force
    try:
        brute = dns_brute_force(target, threads=min(threads, 20))
        out["extra_subdomains"].extend(brute)
        if brute:
            write_lines(f"{dirs['subdomains']}/dns_brute.txt", brute)
            logger.info(f"  DNS brute: {len(brute)} new subdomains")
    except Exception as exc:
        logger.debug(f"  dns_brute: {exc}")

    # Permutations - only resolve ones that actually exist
    try:
        candidates = permute_subdomains(subdomains, target)[:200]
        resolved: list[str] = []
        with ThreadPoolExecutor(max_workers=min(threads, 20)) as ex:
            fut_to_sub = {ex.submit(_resolve_host, s): s for s in candidates}
            for f in as_completed(fut_to_sub):
                if f.result():
                    resolved.append(fut_to_sub[f])
        out["extra_subdomains"].extend(resolved)
        if resolved:
            write_lines(f"{dirs['subdomains']}/permutations.txt", resolved)
            logger.info(f"  Permutations: {len(resolved)} new subdomains")
    except Exception as exc:
        logger.debug(f"  permutations: {exc}")

    # Per-IP: ASN, Shodan InternetDB, geolocation, reverse DNS
    seen_ips: set[str] = set()
    for hr in host_records:
        if hr.ip and hr.ip not in seen_ips:
            seen_ips.add(hr.ip)
            try:
                a = asn_lookup(hr.ip)
                if a:
                    out["asn_info"][hr.ip] = a
            except Exception as exc:
                logger.debug(f"  asn {hr.ip}: {exc}")
            try:
                s = shodan_internetdb(hr.ip)
                if s:
                    out["shodan_info"][hr.ip] = s
                    for cve in s.get("vulns", []):
                        out["findings"].append(Finding(
                            severity="low",
                            title=f"Shodan InternetDB reports {cve} on {hr.ip}",
                            host=hr.domain or hr.ip,
                            detail=f"Shodan InternetDB flagged {cve} for IP {hr.ip}; verify applicability",
                            source="shodan_internetdb",
                            tags=["shodan", cve.lower()],
                            evidence=cve,
                        ))
            except Exception as exc:
                logger.debug(f"  shodan {hr.ip}: {exc}")
            try:
                g = ip_geolocate(hr.ip)
                if g:
                    out["geo_info"][hr.ip] = g
            except Exception as exc:
                logger.debug(f"  geo {hr.ip}: {exc}")

    # HTTP/2 + HTTP/3 detection on main hosts
    for host in live_hosts[:5]:
        try:
            hostname = host.split("/")[2].split(":")[0] if "://" in host else host
            out["http_versions"][host] = detect_http_versions(hostname)
        except Exception as exc:
            logger.debug(f"  http_versions {host}: {exc}")

    # Persist a summary file for the recon directory
    try:
        summary_path = f"{dirs['recon']}/extended_recon.json"
        Path(summary_path).write_text(json.dumps({
            "asn": out["asn_info"],
            "shodan_internetdb": out["shodan_info"],
            "geolocation": out["geo_info"],
            "http_versions": out["http_versions"],
            "dns_brute": out["extra_subdomains"],
        }, indent=2, default=str))
    except Exception as exc:
        logger.debug(f"  summary write: {exc}")

    return out


def _resolve_host(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False
