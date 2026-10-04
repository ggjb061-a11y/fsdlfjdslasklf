"""Nikto web server scanner integration.

Handles multiple nikto JSON output shapes:
  * Modern (2.5+):  [ {host, ip, port, vulnerabilities: [...]}, ... ]
  * Older:         { vulnerabilities: [...] }
  * Flat list:     [ {id, msg, url}, ... ]
"""
import json
from pathlib import Path
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run


class NiktoScan(BaseCheck):
    name = "Nikto"
    description = "Run Nikto web server vulnerability scanning"

    def _normalize_vulns(self, data) -> list[dict]:
        """Return a flat list of vulnerability dicts regardless of input shape.

        Nikto JSON ships in three shapes:
          * modern per-host list:  [{host, vulnerabilities: [...]}, ...]
          * legacy single-host:    {host, vulnerabilities: [...]}
          * flat list of findings: [{id, msg, url}, ...]
        The flat shape must be handled OUTSIDE the `vulnerabilities` branch
        because an entry with no `vulnerabilities` key still returns `[]`
        from `.get(...)`, which is a list and used to swallow the entry.
        """
        out: list[dict] = []
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                host_ctx = {k: entry.get(k) for k in ("host", "ip", "port")}
                # Nested shape: has `vulnerabilities` list
                if isinstance(entry.get("vulnerabilities"), list):
                    for v in entry["vulnerabilities"]:
                        if isinstance(v, dict):
                            out.append({**host_ctx, **v})
                    continue
                # Flat shape: the entry itself IS a vulnerability
                if entry.get("id") or entry.get("msg") or entry.get("description"):
                    out.append(entry)
        elif isinstance(data, dict):
            host_ctx = {k: data.get(k) for k in ("host", "ip", "port")}
            vulns = data.get("vulnerabilities", [])
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict):
                        out.append({**host_ctx, **v})
        return out

    @staticmethod
    def _vuln_title(v: dict) -> str:
        """Build a readable finding title from a nikto vulnerability dict."""
        # Preferred: use `id` if present and non-empty
        for key in ("id", "nikto_id", "osvdb_id", "osvdbid", "msg"):
            val = v.get(key)
            if val and str(val).strip() not in ("", "?", "None"):
                s = str(val).strip()
                # Truncate the message if it's being used as the title
                return s if len(s) < 80 else s[:77] + "..."
        return "Nikto finding"

    @staticmethod
    def _vuln_detail(v: dict) -> str:
        """Build a readable detail from a nikto vulnerability dict."""
        parts = []
        if v.get("msg"):
            parts.append(str(v["msg"])[:300])
        elif v.get("description"):
            parts.append(str(v["description"])[:300])
        if v.get("url"):
            parts.append(f"URL: {v['url']}")
        if v.get("method"):
            parts.append(f"Method: {v['method']}")
        if v.get("references"):
            refs = v["references"] if isinstance(v["references"], str) \
                else " ".join(str(r) for r in (v["references"] or []))
            parts.append(f"Refs: {refs[:120]}")
        if not parts:
            # Last-resort fallback with filtered keys (no metadata flood)
            filtered = {k: val for k, val in v.items()
                         if k in ("id", "osvdbid", "msg", "description",
                                   "url", "method", "nikto_id")
                         and val is not None}
            parts.append(json.dumps(filtered)[:300])
        return "\n".join(parts)

    @staticmethod
    def _vuln_severity(v: dict) -> str:
        """Pick severity from fields nikto exposes.

        Classic nikto exposes no `severity`/`risk`/`level` for most of its
        findings. Defaulting those to `medium` inflates the report with
        banner-leak / ETag-inode / version-disclosure noise. Default to
        `info` and only upgrade on high-impact keywords.
        """
        for key in ("severity", "risk", "level"):
            raw = v.get(key)
            if not raw:
                continue
            low = str(raw).strip().lower()
            if low in ("critical", "high", "medium", "low", "info"):
                return low
        msg = (v.get("msg") or v.get("description") or "").lower()
        if any(k in msg for k in ("rce", "shell", "command execution",
                                    "sql injection", "arbitrary code")):
            return "critical"
        if any(k in msg for k in ("directory listing", "backup file",
                                    "exposed .git", "credentials")):
            return "high"
        if any(k in msg for k in ("directory", "listing", "sensitive",
                                    "outdated", "default page")):
            return "medium"
        return "info"

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
            except Exception as exc:
                self.log.debug(f"  nikto JSON parse ({p.name}): {exc}")
                continue
            vulns = self._normalize_vulns(data)
            for v in vulns:
                host = v.get("host") or self.target
                port = v.get("port")
                self.findings.append(Finding(
                    severity=self._vuln_severity(v),
                    title=f"Nikto: {self._vuln_title(v)}",
                    host=f"{host}:{port}" if port else host,
                    detail=self._vuln_detail(v),
                    source="nikto",
                    url=v.get("url", ""),
                    tags=["nikto", f"nikto-id:{v.get('id', 'unknown')}"],
                ))

        return self.findings
