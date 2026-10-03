"""
Base class for CVE detector plugins.

Each CVE lives in its own file as a small subclass. The orchestrator
(scanner/checks/cves_check.py) instantiates every registered class
and calls its probe() method.

Design invariants:
  * NO out-of-band / external callback (no DNS canary, no interactsh).
    Every signal must come from the HTTP(S) response of the target
    itself.
  * BASELINE comparison: before probing, the orchestrator fetches a
    benign response and passes it in. A match that already appears in
    the baseline must not fire.
  * CONFIRMATION: probes should be idempotent so a flake re-check is cheap.
  * NO EXPLOITATION: payloads are the smallest/safest marker that proves
    the vulnerability exists. We never write files, exec commands, or
    create accounts.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class CVEResult:
    vulnerable: bool
    url: str = ""
    evidence: str = ""
    detail: str = ""


class CVEDetector:
    cve_id: str = ""              # e.g. "CVE-2021-41773"
    title: str = ""               # Short human name
    severity: str = "high"        # critical / high / medium
    affected: str = ""            # Product + version string
    tags: list[str] = []          # extra tags appended to Finding

    def __init__(self, run_fn):
        """run_fn is scanner.utils.run - injected so tests can mock it."""
        self._run = run_fn

    def probe(self, base: str, baseline_body: str) -> Optional[CVEResult]:
        """Return CVEResult(vulnerable=True) when confirmed, else None.

        base          : target base URL, e.g. "https://example.com"
        baseline_body : the body of GET base/ already fetched by the
                        orchestrator; used for FP prevention.
        """
        raise NotImplementedError

    def _get(self, url: str, timeout: int = 8, extra_args: list = None) -> tuple[int, str]:
        args = ["curl", "-sk", "-L", "--max-time", str(timeout),
                "--path-as-is",
                "-w", "\n__STATUS__:%{http_code}"]
        if extra_args:
            args += extra_args
        args.append(url)
        rc, body, _ = self._run(args, timeout=timeout + 4)
        if rc != 0 or not body:
            return 0, ""
        status = 0
        import re
        m = re.search(r"__STATUS__:(\d+)\s*$", body)
        if m:
            status = int(m.group(1))
            body = body[:m.start()]
        return status, body

    def _post(self, url: str, data: str, headers: list[str] = None,
              timeout: int = 8) -> tuple[int, str]:
        args = ["curl", "-sk", "--max-time", str(timeout),
                "-X", "POST",
                "-w", "\n__STATUS__:%{http_code}"]
        for h in (headers or []):
            args += ["-H", h]
        args += ["-d", data, url]
        rc, body, _ = self._run(args, timeout=timeout + 4)
        if rc != 0 or not body:
            return 0, ""
        import re
        status = 0
        m = re.search(r"__STATUS__:(\d+)\s*$", body)
        if m:
            status = int(m.group(1))
            body = body[:m.start()]
        return status, body
