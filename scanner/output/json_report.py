"""Dedicated JSON output module (kept separate for pluggable formats)."""
import json
import logging
from pathlib import Path

logger = logging.getLogger("autoscan.output.json")


def generate_json(result) -> str:
    """Generate machine-readable JSON report."""
    counts = result.count_by_severity()
    summary = {
        "target": result.target,
        "scan_date": result.scan_date,
        "severity_counts": counts,
        "total_findings": len(result.findings),
        "total_subdomains": len(result.subdomains),
        "total_live_hosts": len(result.live_hosts),
        "total_urls": len(result.urls),
        "total_js_secrets": len(result.js_secrets),
        "findings": [
            {"severity": f.severity, "title": f.title, "host": f.host,
             "source": f.source, "detail": f.detail, "url": f.url, "tags": f.tags}
            for f in result.sorted_findings()
        ],
        "js_secrets": [
            {"severity": s.severity, "pattern": s.pattern_name,
             "file": s.file_url, "line": s.line, "match": s.match}
            for s in result.js_secrets
        ],
        "subdomains": result.subdomains,
        "live_hosts": result.live_hosts,
        "dns": result.dns_records,
        "http_methods": result.allowed_methods,
        "urls_login": [u.url for u in result.urls if u.is_login],
        "urls_sensitive": [u.url for u in result.urls if u.is_sensitive_file],
        "urls_api": [u.url for u in result.urls if u.is_api],
        "urls_js": [u.url for u in result.urls if u.is_js],
        "emails": getattr(result, "emails", []),
        "cms_info": getattr(result, "cms_info", {}),
        "found_params": getattr(result, "found_params", {}),
        "google_dorks": getattr(result, "google_dorks", []),
        "ports_raw": getattr(result, "ports_raw", []),
        "whois": result.whois,
        "waf": result.waf,
    }
    path = f"{result.base_dir}/06_reports/summary.json"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(summary, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info(f"  JSON report: {path}")
    return path
