"""JWT weakness analyzer: decodes JWTs and tests for alg=none, weak HS256 secrets."""
import base64
import hashlib
import hmac
import json
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class JWTWeaknessCheck(BaseCheck):
    """Discover JWT tokens in responses and audit them."""

    name = "JWT Weakness"
    description = "Audit JWT tokens for alg=none and weak HS256 secrets"

    JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

    COMMON_SECRETS = [
        "secret", "password", "jwt_secret", "my_secret", "key",
        "jwtkey", "jwtsecret", "mysecret", "s3cr3t", "default",
        "changeme", "admin", "test", "example", "null", "", "none",
    ]

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @classmethod
    def _b64url_decode(cls, data: str) -> bytes:
        pad = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + pad)

    def _decode_header(self, token: str) -> dict:
        try:
            header_part = token.split(".")[0]
            return json.loads(self._b64url_decode(header_part))
        except Exception:
            return {}

    def _try_weak_secret(self, token: str) -> str | None:
        try:
            h, p, s = token.split(".")
        except ValueError:
            return None
        message = f"{h}.{p}".encode()
        for secret in self.COMMON_SECRETS:
            mac = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            if self._b64url(mac) == s:
                return secret
        return None

    def execute(self) -> list[Finding]:
        seen_tokens = set()
        for base in self._hosts():
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "8", base],
                timeout=12,
            )
            text = (body or "")
            rc2, headers, _ = run(
                ["curl", "-sI", "--max-time", "6", base],
                timeout=10,
            )
            text += "\n" + (headers or "")

            for match in self.JWT_RE.findall(text):
                if match in seen_tokens:
                    continue
                seen_tokens.add(match)

                header = self._decode_header(match)
                alg = (header.get("alg") or "").lower()
                kid = header.get("kid")

                if alg == "none":
                    self.findings.append(Finding(
                        severity="critical",
                        title="JWT alg=none Accepted",
                        host=base,
                        detail="Token issued with alg=none - signature not verified",
                        source="jwt",
                        url=base,
                        evidence=match[:60] + "...",
                    ))

                if alg == "hs256":
                    weak = self._try_weak_secret(match)
                    if weak is not None:
                        self.findings.append(Finding(
                            severity="critical",
                            title=f"JWT HS256 Weak Secret Found: '{weak or '<empty>'}'",
                            host=base,
                            detail=f"Token signed with trivially guessable secret",
                            source="jwt",
                            url=base,
                            evidence=f"secret={weak!r}",
                        ))

                if kid and (".." in str(kid) or "/" in str(kid)):
                    self.findings.append(Finding(
                        severity="high",
                        title="JWT kid Header Path Traversal Suspicion",
                        host=base,
                        detail=f"kid header contains suspicious path chars: {kid}",
                        source="jwt",
                        url=base,
                    ))

        return self.findings
