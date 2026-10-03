"""Insecure deserialization detection: look for serialized blobs in cookies/params."""
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class DeserializationCheck(BaseCheck):
    """Scan Set-Cookie, hidden inputs, and URL params for serialized-blob magic prefixes."""

    name = "Deserialization"
    description = "Detect serialized blobs (Java, PHP, .NET, pickle, Ruby) that may be deserialization sinks"

    SIGNATURES = [
        ("Java (ObjectInputStream)",   re.compile(r"rO0AB[A-Za-z0-9+/=]+")),
        ("Java (hex ac ed 00 05)",     re.compile(r"\\xac\\xed\\x00\\x05")),
        ("PHP serialize",              re.compile(r"O:\d+:\"[A-Za-z_\\]+\":\d+:\{")),
        (".NET __VIEWSTATE",           re.compile(r"__VIEWSTATE")),
        ("Python pickle (gASV)",       re.compile(r"gASV[A-Za-z0-9+/=]{10,}")),
        ("Python pickle (hex 80 04)",  re.compile(r"\\x80\\x04")),
        ("Ruby Marshal",               re.compile(r"BAh[A-Za-z0-9+/=]{10,}")),
        ("Node.js serialize",          re.compile(r"_\$\$ND_FUNC\$\$_")),
    ]

    def _scan(self, text: str, host: str, source: str) -> None:
        for name, rx in self.SIGNATURES:
            m = rx.search(text)
            if m:
                # A serialized blob in a cookie/form proves the server
                # emits a serialized object, not that it deserializes
                # attacker-controlled input. It's a strong hint worth
                # investigation; severity stays MEDIUM until an exploit
                # path is confirmed by a dedicated check or manual follow-up.
                self.findings.append(Finding(
                    severity="medium",
                    title=f"Serialized Blob Detected ({name})",
                    host=host,
                    detail=(
                        f"Potential deserialization sink via {source}; "
                        f"signature matched: {name}. "
                        f"The server round-trips a {name} blob through user-"
                        f"accessible storage. Verify whether modifying it "
                        f"triggers server-side deserialization (gadget chain) "
                        f"before escalating."
                    ),
                    source="deserialization",
                    url=host,
                    evidence=m.group(0)[:120],
                ))
                break

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            rc, headers, _ = run(
                ["curl", "-sI", "--max-time", "8", base],
                timeout=12,
            )
            if rc == 0 and headers:
                for line in headers.splitlines():
                    if line.lower().startswith("set-cookie:"):
                        value = line.split(":", 1)[1].strip()
                        self._scan(value, base, "Set-Cookie header")

            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "10", base],
                timeout=15,
            )
            if rc == 0 and body:
                for m in re.finditer(r'<input[^>]+value="([^"]+)"', body, re.IGNORECASE):
                    self._scan(m.group(1), base, "hidden form field")
                if "__VIEWSTATE" in body:
                    self.findings.append(Finding(
                        severity="info",
                        title="ASP.NET __VIEWSTATE Present",
                        host=base,
                        detail="Page uses ASP.NET __VIEWSTATE; check for ViewStateUserKey / signing",
                        source="deserialization",
                        url=base,
                    ))

        return self.findings
