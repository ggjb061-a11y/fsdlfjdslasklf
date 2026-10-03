"""
CVE orchestrator check.

Iterates over every registered CVEDetector in scanner/checks/cves/
and runs its probe against each live host. Fetches ONE benign baseline
per host and shares it across detectors to:

  1. Give each detector FP-prevention context (indicator-in-baseline guard).
  2. Avoid redundant HTTP traffic.
"""
from .base import BaseCheck
from ..models import Finding
from ..utils import run
from .cves import ALL_CVE_DETECTORS


class CVEMegaCheck(BaseCheck):
    """Run 20+ real CVE detectors per host, no external callbacks required."""

    name = "CVE Suite"
    description = (
        "20+ dedicated detectors for high-impact CVEs (Apache 2.4.49/50 path "
        "traversal, WebLogic WLS/Async/Console, F5 TMUI, JBoss, Elasticsearch, "
        "Solr, Kibana, Citrix NetScaler, Spring Gateway/Function, VMware "
        "vCenter, Rails Accept, Grafana SSRF, WSO2, PaperCut, Struts REST, "
        "PHP-FPM/nginx)"
    )

    def _fetch_baseline(self, base: str) -> str:
        rc, body, _ = run(["curl", "-skL", "--max-time", "8", base],
                           timeout=12)
        return body or ""

    def execute(self) -> list[Finding]:
        for base in self._hosts(5):
            try:
                baseline = self._fetch_baseline(base)
            except Exception as exc:
                self.log.debug(f"  cve baseline {base}: {exc}")
                baseline = ""

            for cls in ALL_CVE_DETECTORS:
                try:
                    detector = cls(run)
                    result = detector.probe(base, baseline)
                except Exception as exc:
                    self.log.debug(f"  {cls.__name__}({base}): {exc}")
                    continue
                if result is None or not result.vulnerable:
                    continue
                self.findings.append(Finding(
                    severity=cls.severity,
                    title=f"{cls.cve_id} - {cls.title}",
                    host=base,
                    detail=(
                        f"CVE: {cls.cve_id}\n"
                        f"Affected: {cls.affected}\n"
                        f"{result.detail}"
                    ),
                    source=f"cve:{cls.cve_id.lower()}",
                    url=result.url,
                    tags=["cve", cls.cve_id.lower(), *cls.tags],
                    evidence=result.evidence,
                ))
        return self.findings
