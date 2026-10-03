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
                    entries = data if isinstance(data, list) else data.get("findings", [])
                    for entry in entries:
                        sev_map = {"CRITICAL": "critical", "HIGH": "high",
                                   "MEDIUM": "medium", "LOW": "low",
                                   "INFO": "info", "OK": "info", "NOT OK": "medium"}
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
                except Exception as exc:
                    self.log.warning(f"  testssl.json parse failed: {exc}")

        elif which("sslscan"):
            txt_path = f"{out_dir}/sslscan.txt"
            run(["sslscan", "--xml", f"{out_dir}/sslscan.xml", self.target],
                output_file=txt_path, timeout=120)
            self._parse_sslscan(txt_path)

        elif which("openssl"):
            rc, out, err = run(
                ["openssl", "s_client", "-connect", f"{self.target}:443",
                 "-servername", self.target],
                stdin_data="", timeout=15,
            )
            text = (out or "") + (err or "")
            Path(f"{out_dir}/openssl.txt").write_text(text)
            self._parse_openssl(text)

        return self.findings

    def _parse_sslscan(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        content = p.read_text(errors="replace")
        if "SSLv2" in content and "accepted" in content.lower():
            self.findings.append(Finding(
                severity="high", title="SSL/TLS: SSLv2 Accepted",
                host=self.target, detail="SSLv2 protocol is accepted - critically weak",
                source="sslscan",
            ))
        if "SSLv3" in content and "accepted" in content.lower():
            self.findings.append(Finding(
                severity="high", title="SSL/TLS: SSLv3 Accepted (POODLE)",
                host=self.target, detail="SSLv3 protocol accepted - POODLE attack",
                source="sslscan",
            ))
        if "TLSv1.0" in content and "enabled" in content.lower():
            # TLSv1.0 is deprecated and PCI-DSS flags it, but BEAST/POODLE
            # are heavily mitigated client-side; realistic risk is LOW on
            # modern browsers unless the server also serves old clients.
            self.findings.append(Finding(
                severity="low", title="SSL/TLS: TLSv1.0 Enabled (deprecated)",
                host=self.target,
                detail="TLSv1.0 is enabled. Deprecated by PCI-DSS and all major browsers; attack surface limited to legacy clients.",
                source="sslscan",
            ))

    def _parse_openssl(self, text: str) -> None:
        import re
        m = re.search(r"notAfter\s*=\s*(.+)", text)
        if m:
            self.findings.append(Finding(
                severity="info", title="SSL/TLS: Certificate expiry info",
                host=self.target, detail=f"Certificate expires: {m.group(1).strip()}",
                source="openssl",
            ))
        if "self signed" in text.lower() or "self-signed" in text.lower():
            # Self-signed cert is a trust-chain issue, not an exploitation
            # path; browsers block or warn, so it's a LOW severity misconfig
            # unless combined with mTLS/API clients that ignore validation.
            self.findings.append(Finding(
                severity="low", title="SSL/TLS: Self-Signed Certificate",
                host=self.target,
                detail="Server presents self-signed certificate; clients that ignore trust chain are vulnerable to MITM.",
                source="openssl",
            ))
        if re.search(r"Protocol\s*:\s*SSLv[23]", text):
            self.findings.append(Finding(
                severity="high", title="SSL/TLS: Weak Protocol Negotiated",
                host=self.target, detail="openssl negotiated SSLv2/SSLv3",
                source="openssl",
            ))
