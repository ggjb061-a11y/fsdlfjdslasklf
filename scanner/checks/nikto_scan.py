"""Nikto web server scanner integration."""
import json
from pathlib import Path
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run


class NiktoScan(BaseCheck):
    name = "Nikto"
    description = "Run Nikto web server vulnerability scanning"

    def execute(self) -> list[Finding]:
        if not which("nikto"):
            self.log.warning("  nikto not installed")
            return []

        targets = self._hosts()
        for i, host in enumerate(targets):
            out_txt  = f"{self.dirs['nikto']}/nikto_{i}.txt"
            out_json = f"{self.dirs['nikto']}/nikto_{i}.json"
            run(["nikto", "-h", host, "-o", out_txt,
                 "-Format", "txt", "-maxtime", "5m"], timeout=360)
            run(["nikto", "-h", host, "-o", out_json,
                 "-Format", "json", "-maxtime", "5m"], timeout=360)

        for p in Path(self.dirs["nikto"]).glob("*.json"):
            try:
                data = json.loads(p.read_text(errors="replace"))
                vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
                for v in (vulns or []):
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"Nikto: {v.get('id', '?')}",
                        host=v.get("host", self.target),
                        detail=v.get("msg", v.get("description", str(v))),
                        source="nikto",
                        url=v.get("url", ""),
                    ))
            except Exception:
                pass

        return self.findings
