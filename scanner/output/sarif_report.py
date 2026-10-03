"""SARIF 2.1.0 output for GitHub Advanced Security code-scanning integration."""
import json
import logging
from pathlib import Path

logger = logging.getLogger("autoscan.output.sarif")

SEV_TO_SARIF = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}


def generate_sarif(result) -> str:
    """Emit a SARIF 2.1.0 file containing all findings."""
    rules = {}
    results = []

    for f in result.sorted_findings():
        rule_id = f.source or "finding"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": f.title},
                "defaultConfiguration": {"level": SEV_TO_SARIF.get(f.severity.lower(), "note")},
            }
        results.append({
            "ruleId": rule_id,
            "level":  SEV_TO_SARIF.get(f.severity.lower(), "note"),
            "message": {"text": f"{f.title}: {f.detail}"},
            "properties": {
                "severity": f.severity,
                "host": f.host,
                "tags": f.tags,
                "url": f.url,
                "evidence": f.evidence,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url or f.host or result.target},
                },
            }],
        })

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AutoVulnScan",
                    "informationUri": "https://github.com/ggjb061-a11y/fsdlfjdslasklf",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "automationDetails": {"id": f"autovulnscan/{result.target}/{result.scan_date}"},
        }],
    }

    path = f"{result.base_dir}/06_reports/report.sarif"
    Path(path).write_text(json.dumps(sarif, indent=2, ensure_ascii=False))
    logger.info(f"  SARIF report: {path}")
    return path
