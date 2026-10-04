"""Dedicated JSON output module (kept separate for pluggable formats)."""
import json
import logging
from dataclasses import asdict, is_dataclass
from pathlib import Path

logger = logging.getLogger("autoscan.output.json")


def _as_dict(obj):
    """asdict() for dataclasses, vars() for plain objects, else obj."""
    if obj is None:
        return None
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return obj


def _json_default(o):
    """Fallback encoder - lists for sets, isoformat for datetimes, repr for the rest."""
    if isinstance(o, (set, frozenset)):
        return sorted(list(o))
    if hasattr(o, "isoformat"):
        return o.isoformat()
    return repr(o)


def generate_json(result) -> str:
    """Generate machine-readable JSON report."""
    counts = result.count_by_severity()
    owasp_counts = (
        result.count_by_owasp() if hasattr(result, "count_by_owasp") else {}
    )
    total_cvss = (
        result.total_cvss() if hasattr(result, "total_cvss") else 0.0
    )
    # Use Finding.to_dict() where available so derived fields
    # (cvss_estimate, owasp, sev_order) land in the machine-readable
    # artifact, matching what the HTML / Markdown reports show.
    def _finding_dict(f):
        if hasattr(f, "to_dict"):
            return f.to_dict()
        return {
            "severity": f.severity, "title": f.title, "host": f.host,
            "source": f.source, "detail": f.detail, "url": f.url,
            "tags": f.tags, "evidence": getattr(f, "evidence", ""),
        }

    summary = {
        "target": result.target,
        "scan_date": result.scan_date,
        "severity_counts": counts,
        "owasp_counts": owasp_counts,
        "total_cvss_estimate": round(total_cvss, 1),
        "total_findings": len(result.findings),
        "total_subdomains": len(result.subdomains),
        "total_live_hosts": len(result.live_hosts),
        "total_urls": len(result.urls),
        "total_js_secrets": len(result.js_secrets),
        "findings": [_finding_dict(f) for f in result.sorted_findings()],
        "js_secrets": [
            {"severity": s.severity, "pattern": s.pattern_name,
             "file": s.file_url, "line": s.line, "match": s.match}
            for s in result.js_secrets
        ],
        "js_endpoints": getattr(result, "js_endpoints", []),
        "subdomains": result.subdomains,
        "live_hosts": result.live_hosts,
        # Full HostRecord objects (ip, status, title, server, technologies,
        # open_ports, cdn, waf, http_methods). Lost in the old flat
        # live_hosts list.
        "host_records": [_as_dict(h) for h in getattr(result, "host_records", [])],
        "dns": result.dns_records,
        "http_methods": result.allowed_methods,
        "urls": [_as_dict(u) for u in result.urls],
        "urls_login": [u.url for u in result.urls if u.is_login],
        "urls_sensitive": [u.url for u in result.urls if u.is_sensitive_file],
        "urls_api": [u.url for u in result.urls if u.is_api],
        "urls_js": [u.url for u in result.urls if u.is_js],
        "emails": getattr(result, "emails", []),
        "cms_info": getattr(result, "cms_info", {}),
        "found_params": getattr(result, "found_params", {}),
        "google_dorks": getattr(result, "google_dorks", []),
        "ports_raw": getattr(result, "ports_raw", []),
        # ASN / Shodan / Geo / HTTP-version intel - populated by recon_extended
        # and shown in the HTML report, but the old JSON output silently
        # dropped them.
        "asn_info": getattr(result, "asn_info", {}),
        "shodan_info": getattr(result, "shodan_info", {}),
        "geo_info": getattr(result, "geo_info", {}),
        "http_versions": getattr(result, "http_versions", {}),
        "whois": result.whois,
        "waf": result.waf,
    }
    path = f"{result.base_dir}/06_reports/summary.json"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    # Serialize once; on TypeError, fall back to repr for the offending key
    # so a single bad entry does not kill the entire JSON export.
    try:
        body = json.dumps(summary, indent=2, default=_json_default, ensure_ascii=False)
    except TypeError as exc:
        logger.warning(f"  JSON serialization fell back on repr: {exc}")
        body = json.dumps(summary, indent=2, default=repr, ensure_ascii=False)
    Path(path).write_text(body, encoding="utf-8")
    logger.info(f"  JSON report: {path}")
    return path
