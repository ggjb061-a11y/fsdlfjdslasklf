"""
Scan checkpoint/resume capability.

Persists scan state after each phase so interrupted scans can be resumed.
State file: <base_dir>/.checkpoint.json
"""
import json
import logging
from pathlib import Path
from dataclasses import asdict, is_dataclass, fields

logger = logging.getLogger("autoscan.checkpoint")


def _safe_init(cls, data: dict):
    """Build cls(**data) tolerating extra/missing fields from older checkpoints."""
    known = {f.name for f in fields(cls)}
    filtered = {k: v for k, v in data.items() if k in known}
    try:
        return cls(**filtered)
    except TypeError as exc:
        logger.warning(f"  Could not restore {cls.__name__}: {exc}")
        return None


class CheckpointManager:
    """Manages persisting and restoring scan state across phases."""

    def __init__(self, base_dir: str):
        self.path = Path(base_dir) / ".checkpoint.json"
        self.state: dict = {"phases_done": [], "data": {}}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            self.state = json.loads(self.path.read_text())
            logger.info(f"  Checkpoint loaded: {len(self.state.get('phases_done', []))} phases already complete")
        except Exception as exc:
            logger.warning(f"  Could not load checkpoint: {exc}")
            self.state = {"phases_done": [], "data": {}}

    def _serializable(self, obj):
        """Convert dataclasses/sets to JSON-serializable form."""
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, (set, tuple)):
            return list(obj)
        if isinstance(obj, dict):
            return {k: self._serializable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._serializable(v) for v in obj]
        return obj

    def mark_done(self, phase: str, data: dict = None) -> None:
        """Mark a phase complete and optionally save its data."""
        if phase not in self.state["phases_done"]:
            self.state["phases_done"].append(phase)
        if data:
            self.state["data"][phase] = self._serializable(data)
        # Atomic write: tmp + rename, so SIGINT between phases cannot
        # leave a half-written checkpoint behind.
        try:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.state, indent=2, default=str))
            tmp.replace(self.path)
        except Exception as exc:
            logger.warning(f"  Could not save checkpoint: {exc}")

    def is_done(self, phase: str) -> bool:
        return phase in self.state.get("phases_done", [])

    def get_data(self, phase: str) -> dict:
        return self.state.get("data", {}).get(phase, {})

    def restore_result(self, result) -> None:
        """Restore a ScanResult from checkpoint data (used on --resume)."""
        from .models import URLRecord, Finding, HostRecord, JSSecret

        data = self.state.get("data", {})

        def _list(cls, items):
            return [x for x in (_safe_init(cls, i) for i in (items or [])) if x is not None]

        if "recon" in data:
            r = data["recon"]
            result.subdomains = r.get("subdomains", [])
            result.live_hosts = r.get("live_hosts", [])
            result.dns_records = r.get("dns_records", {})
            result.whois = r.get("whois", "")
            result.waf = r.get("waf", "")
            result.ports_raw = r.get("ports_raw", [])
            result.google_dorks = r.get("google_dorks", [])
            result.host_records = _list(HostRecord, r.get("host_records", []))

        if "passive" in data:
            p = data["passive"]
            result.urls.extend(_list(URLRecord, p.get("urls", [])))
            result.findings.extend(_list(Finding, p.get("findings", [])))
            result.emails = p.get("emails", [])
            result.cms_info = p.get("cms_info", {})

        if "crawl" in data:
            c = data["crawl"]
            result.urls.extend(_list(URLRecord, c.get("urls", [])))

        if "js" in data:
            j = data["js"]
            result.js_secrets = _list(JSSecret, j.get("secrets", []))
            result.js_endpoints = j.get("endpoints", [])
            result.findings.extend(_list(Finding, j.get("findings", [])))

        if "params" in data:
            result.found_params = data["params"].get("found_params", {})
            result.findings.extend(_list(Finding, data["params"].get("findings", [])))

        if "methods" in data:
            result.allowed_methods = data["methods"].get("allowed_methods", {})
            result.findings.extend(_list(Finding, data["methods"].get("findings", [])))

        if "vuln" in data:
            result.findings.extend(_list(Finding, data["vuln"].get("findings", [])))
