"""SSL/TLS configuration testing."""
import json
from pathlib import Path
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run


class SSLCheck(BaseCheck):
    name = "SSL/TLS"
    description = "Analyze SSL/TLS configuration for weak ciphers and protocols"

    def execute(self) -> list[Finding]:
        out_dir = self.dirs["ssl"]

        if which("testssl.sh") or which("testssl"):
            binary = "testssl.sh" if which("testssl.sh") else "testssl"
            run(
                [binary,
                 "--jsonfile", f"{out_dir}/testssl.json",
                 "--logfile",  f"{out_dir}/testssl.log",
                 "--severity", "LOW",
                 "--color", "0",
                 f"{self.target}:443"],
                timeout=300,
            )
            p = Path(f"{out_dir}/testssl.json")
            if p.exists():
                try:
                    data = json.loads(p.read_text(errors="replace"))
                    for entry in data.get("findings", []):
                        sev_map = {"CRITICAL": "critical", "HIGH": "high",
                                   "MEDIUM": "medium", "LOW": "low",
                                   "INFO": "info", "OK": "info", "NOT ok": "medium"}
                        raw_sev = entry.get("severity", "INFO")
                        sev = sev_map.get(raw_sev.upper(), "info")
                        if sev in ("medium", "high", "critical"):
                            self.findings.append(Finding(
                                severity=sev,
                                title=f"SSL/TLS: {entry.get('id', '?')}",
                                host=self.target,
                                detail=entry.get("finding", ""),
                                source="testssl",
                            ))
                except Exception:
                    pass

        elif which("sslscan"):
            run(["sslscan", "--xml", f"{out_dir}/sslscan.xml", self.target],
                output_file=f"{out_dir}/sslscan.txt", timeout=120)

        elif which("openssl"):
            rc, out, err = run(
                ["openssl", "s_client", "-connect", f"{self.target}:443",
                 "-servername", self.target],
                stdin_data="", timeout=15,
            )
            Path(f"{out_dir}/openssl.txt").write_text(out + err)

        return self.findings
