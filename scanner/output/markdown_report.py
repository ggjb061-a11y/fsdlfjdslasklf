"""Markdown report generator - produces a GitHub-flavored markdown report."""
import logging
from pathlib import Path

logger = logging.getLogger("autoscan.output.markdown")

SEV_EMOJI = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]",
    "medium":   "[MEDIUM]",
    "low":      "[LOW]",
    "info":     "[INFO]",
}


def _h1(s: str) -> str:
    return f"# {s}\n\n"


def _h2(s: str) -> str:
    return f"\n## {s}\n\n"


def _h3(s: str) -> str:
    return f"\n### {s}\n\n"


def _table(headers: list, rows: list) -> str:
    if not rows:
        return "_No data._\n\n"
    out = "| " + " | ".join(headers) + " |\n"
    out += "| " + " | ".join(["---"] * len(headers)) + " |\n"
    for row in rows:
        safe = [str(c).replace("|", "\\|").replace("\n", " ")[:200] for c in row]
        out += "| " + " | ".join(safe) + " |\n"
    return out + "\n"


def _code_block(content: str, lang: str = "") -> str:
    return f"```{lang}\n{content}\n```\n\n"


def generate_markdown(result) -> str:
    """Generate markdown report. Returns the path to the written file."""
    counts = result.count_by_severity()
    md = []

    md.append(_h1(f"AutoVulnScan Report - {result.target}"))
    md.append(f"**Scan Date:** {result.scan_date}  \n")
    md.append(f"**Target:** `{result.target}`  \n")
    md.append(f"**Base Directory:** `{result.base_dir}`  \n\n")

    md.append(_h2("Severity Summary"))
    md.append(_table(
        ["Severity", "Count"],
        [
            [f"{SEV_EMOJI['critical']} Critical", counts["critical"]],
            [f"{SEV_EMOJI['high']} High", counts["high"]],
            [f"{SEV_EMOJI['medium']} Medium", counts["medium"]],
            [f"{SEV_EMOJI['low']} Low", counts["low"]],
            [f"{SEV_EMOJI['info']} Info", counts["info"]],
            ["**Total**", f"**{len(result.findings)}**"],
        ],
    ))

    md.append(_h2("Scan Statistics"))
    md.append(_table(
        ["Metric", "Count"],
        [
            ["Subdomains", len(result.subdomains)],
            ["Live Hosts", len(result.live_hosts)],
            ["URLs Collected", len(result.urls)],
            ["JS Secrets", len(result.js_secrets)],
            ["Emails", len(getattr(result, "emails", []))],
            ["Open Ports", len(getattr(result, "ports_raw", []))],
            ["Google Dorks", len(getattr(result, "google_dorks", []))],
        ],
    ))

    md.append(_h2("Findings"))
    findings = result.sorted_findings()
    if findings:
        for sev in ("critical", "high", "medium", "low", "info"):
            sev_findings = [f for f in findings if f.severity.lower() == sev]
            if not sev_findings:
                continue
            md.append(_h3(f"{SEV_EMOJI[sev]} {sev.title()} ({len(sev_findings)})"))
            md.append(_table(
                ["Title", "Host", "Source", "URL", "Detail"],
                [
                    [f.title, f.host, f.source, f.url or "-", f.detail[:150]]
                    for f in sev_findings
                ],
            ))
    else:
        md.append("_No findings._\n\n")

    if result.js_secrets:
        md.append(_h2("JS Secrets"))
        md.append(_table(
            ["Severity", "Pattern", "File", "Line", "Match"],
            [
                [SEV_EMOJI.get(s.severity, s.severity), s.pattern_name,
                 s.file_url, s.line, f"`{s.match[:60]}`"]
                for s in result.js_secrets
            ],
        ))

    if result.subdomains:
        md.append(_h2(f"Subdomains ({len(result.subdomains)})"))
        chunks = [result.subdomains[i:i+5] for i in range(0, len(result.subdomains), 5)]
        for chunk in chunks[:40]:
            md.append("- " + "  \n- ".join(f"`{s}`" for s in chunk) + "\n")
        md.append("\n")

    host_records = getattr(result, "host_records", [])
    if host_records:
        md.append(_h2(f"Live Hosts ({len(host_records)})"))
        md.append(_table(
            ["Domain", "IP", "Status", "Server", "Title", "Technologies"],
            [
                [h.domain, h.ip or "-", h.status or "-", h.server or "-",
                 (h.title or "")[:40], ", ".join(h.technologies[:5])]
                for h in host_records
            ],
        ))

    if result.dns_records:
        md.append(_h2("DNS Records"))
        md.append(_table(
            ["Type", "Values"],
            [[rtype, ", ".join(vals)] for rtype, vals in result.dns_records.items()],
        ))

    if result.urls:
        md.append(_h2(f"URLs ({len(result.urls)})"))
        login = [u for u in result.urls if u.is_login]
        sensitive = [u for u in result.urls if u.is_sensitive_file]
        api = [u for u in result.urls if u.is_api]
        if login:
            md.append(_h3(f"Login/Auth Pages ({len(login)})"))
            for u in login[:30]:
                md.append(f"- [{u.url}]({u.url}) `{u.status or ''}`\n")
            md.append("\n")
        if sensitive:
            md.append(_h3(f"Sensitive Files ({len(sensitive)})"))
            for u in sensitive[:30]:
                md.append(f"- [{u.url}]({u.url}) `{u.status or ''}`\n")
            md.append("\n")
        if api:
            md.append(_h3(f"API Endpoints ({len(api)})"))
            for u in api[:30]:
                md.append(f"- [{u.url}]({u.url}) `{u.status or ''}`\n")
            md.append("\n")

    endpoints = getattr(result, "js_endpoints", [])
    if endpoints:
        md.append(_h2(f"JS Endpoints ({len(endpoints)})"))
        for e in endpoints[:100]:
            md.append(f"- `{e}`\n")
        md.append("\n")

    if result.found_params:
        md.append(_h2("Discovered Parameters"))
        md.append(_table(
            ["Endpoint", "Parameters"],
            [[url, ", ".join(params)] for url, params in result.found_params.items()],
        ))

    if result.allowed_methods:
        md.append(_h2("HTTP Methods"))
        md.append(_table(
            ["Host", "Allowed Methods"],
            [[host, ", ".join(meths)] for host, meths in result.allowed_methods.items()],
        ))

    emails = getattr(result, "emails", [])
    if emails:
        md.append(_h2(f"Emails ({len(emails)})"))
        for e in emails:
            md.append(f"- `{e}`\n")
        md.append("\n")

    cms = getattr(result, "cms_info", {})
    if cms:
        md.append(_h2("CMS Detection"))
        md.append(_table(["Host", "CMS/Framework"], [[h, c] for h, c in cms.items()]))

    ports = getattr(result, "ports_raw", [])
    if ports:
        md.append(_h2("Open Ports"))
        md.append(_code_block("\n".join(ports[:50])))

    dorks = getattr(result, "google_dorks", [])
    if dorks:
        md.append(_h2(f"Google Dorks ({len(dorks)})"))
        md.append("Copy these into Google for manual recon:\n\n")
        for d in dorks:
            md.append(f"- `{d}`\n")
        md.append("\n")

    if result.whois:
        md.append(_h2("WHOIS"))
        md.append(_code_block(result.whois[:1500]))

    if result.waf:
        md.append(_h2("WAF Detection"))
        md.append(_code_block(result.waf[:500]))

    md.append("\n---\n\n")
    md.append(f"_Report generated by AutoVulnScan v3.0 - Authorized testing only_\n")

    out_path = f"{result.base_dir}/06_reports/report.md"
    Path(out_path).write_text("".join(md))
    logger.info(f"  Markdown report: {out_path}")
    return out_path
