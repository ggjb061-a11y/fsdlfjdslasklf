"""
OAuth / SAML / OIDC misconfiguration detection.

Checks:
  1. /.well-known/openid-configuration - OIDC discovery leaks endpoints
  2. redirect_uri wildcard: send auth request with attacker-controlled uri
     and verify the server honors it in the redirect.
  3. Missing/weak state parameter enforcement
  4. SAML metadata exposed at /saml/metadata or /saml/sso/metadata
"""
import json
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run
from ..constants import ATTACKER_CANARY


class OAuthSAMLCheck(BaseCheck):
    name = "OAuth/SAML"
    description = "OAuth, OIDC, and SAML misconfiguration detection"

    OIDC_WELL_KNOWN = "/.well-known/openid-configuration"
    AUTHORIZE_PATHS = [
        "/oauth/authorize", "/oauth2/authorize", "/authorize",
        "/connect/authorize", "/openid-connect/authorize",
    ]
    SAML_METADATA_PATHS = [
        "/saml/metadata", "/saml/sso/metadata", "/simplesaml/saml2/idp/metadata.php",
        "/auth/saml/metadata", "/sso/saml/metadata",
    ]

    def _fetch(self, url: str, follow: bool = False,
               extra_args: list = None, timeout: int = 8) -> tuple[int, str, str]:
        args = ["curl", "-sk", "--max-time", str(timeout),
                "-w", "\n__STATUS__:%{http_code}\n__LOCATION__:%{redirect_url}"]
        if follow:
            args.append("-L")
        if extra_args:
            args += extra_args
        args.append(url)
        rc, out, _ = run(args, timeout=timeout + 4)
        if rc != 0 or not out:
            return 0, "", ""
        import re
        status = 0
        location = ""
        m = re.search(r"__STATUS__:(\d+)", out)
        if m: status = int(m.group(1))
        m2 = re.search(r"__LOCATION__:(.+?)\s*$", out)
        if m2: location = m2.group(1).strip()
        # Strip our markers for body
        body = re.sub(r"\n__STATUS__:.*$", "", out, flags=re.DOTALL)
        return status, body, location

    def _check_oidc(self, base: str) -> dict | None:
        """Returns the OIDC config if found, else None."""
        url = base + self.OIDC_WELL_KNOWN
        status, body, _ = self._fetch(url)
        if status != 200 or not body:
            return None
        try:
            cfg = json.loads(body)
        except Exception:
            return None
        if "issuer" not in cfg or "authorization_endpoint" not in cfg:
            return None
        self.findings.append(Finding(
            severity="info",
            title="OIDC Discovery exposed",
            host=base,
            detail=(
                f"OIDC /.well-known/openid-configuration is public. Issuer: "
                f"{cfg.get('issuer')}. Lists {len(cfg)} endpoints."
            ),
            source="oauth_saml",
            url=url,
            tags=["oidc", "discovery-exposed"],
            evidence=json.dumps(cfg)[:400],
        ))
        return cfg

    def _check_redirect_uri_wildcard(self, authorize_url: str) -> None:
        canary = f"https://{ATTACKER_CANARY}/callback"
        probe = (f"{authorize_url}?response_type=code"
                 f"&client_id=test&redirect_uri={urllib.parse.quote(canary)}"
                 f"&state=xyz")
        status, body, location = self._fetch(probe, follow=False)
        # If server redirects to our attacker URL, it accepts the uri
        if location and ATTACKER_CANARY in location:
            # Strip code=/access_token=/id_token=/state= values before
            # persisting - implicit-flow IdPs put live credentials in the
            # Location fragment or query, and reports flow to shared systems.
            try:
                parsed = urllib.parse.urlparse(location)
                query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                redacted_q = [
                    (k, "<redacted>" if k.lower() in {
                        "code", "access_token", "id_token", "state",
                        "token", "refresh_token", "assertion",
                    } else v)
                    for k, v in query_pairs
                ]
                safe_location = urllib.parse.urlunparse(
                    parsed._replace(
                        query=urllib.parse.urlencode(redacted_q),
                        fragment="<redacted>" if parsed.fragment else "",
                    )
                )
            except Exception:
                safe_location = f"<redacted; ATTACKER_CANARY in Location>"
            self.findings.append(Finding(
                severity="high",
                title="OAuth redirect_uri wildcard (host not pinned)",
                host=authorize_url,
                detail=(
                    f"OAuth authorize endpoint accepts attacker-controlled "
                    f"redirect_uri '{canary}' and redirects to it. Enables "
                    f"authorization-code theft via phishing."
                ),
                source="oauth_saml",
                url=probe,
                tags=["oauth", "redirect-uri", "account-takeover"],
                evidence=safe_location,
            ))

    def _check_state_missing(self, authorize_url: str) -> None:
        probe = (f"{authorize_url}?response_type=code"
                 f"&client_id=test&redirect_uri=https://example.com/cb")
        status, body, location = self._fetch(probe)
        # If server accepts without state (returns 302 to IdP form rather than
        # error), we flag it. Pragmatically: if no "state" in error text.
        if status in (302, 303) and location and "state=" not in location \
           and "state" not in (body or "").lower():
            self.findings.append(Finding(
                severity="medium",
                title="OAuth authorize endpoint accepts missing 'state' parameter",
                host=authorize_url,
                detail=(
                    "No `state` enforcement means the OAuth flow is "
                    "susceptible to CSRF-driven account takeover."
                ),
                source="oauth_saml",
                url=probe,
                tags=["oauth", "csrf", "missing-state"],
            ))

    def _check_saml_metadata(self, base: str) -> None:
        for p in self.SAML_METADATA_PATHS:
            url = base + p
            status, body, _ = self._fetch(url)
            if status == 200 and body and "EntityDescriptor" in body:
                self.findings.append(Finding(
                    severity="info",
                    title=f"SAML metadata exposed: {p}",
                    host=base,
                    detail=(
                        "SAML metadata XML is publicly fetchable. Useful for "
                        "attackers mapping the SSO integration."
                    ),
                    source="oauth_saml",
                    url=url,
                    tags=["saml", "metadata-exposed"],
                    evidence=body[:300],
                ))
                break

    def execute(self) -> list[Finding]:
        for base in self._hosts(3):
            try:
                oidc = self._check_oidc(base)
            except Exception as exc:
                self.log.debug(f"  oidc {base}: {exc}")
                oidc = None

            # Determine authorize endpoint: OIDC-advertised OR enumerated
            auth_endpoints: list[str] = []
            if oidc and "authorization_endpoint" in oidc:
                auth_endpoints.append(oidc["authorization_endpoint"])
            else:
                for p in self.AUTHORIZE_PATHS:
                    url = base + p
                    status, body, _ = self._fetch(url)
                    if status in (200, 302, 400) and ("response_type" in (body or "")
                                                       or "redirect_uri" in (body or "")):
                        auth_endpoints.append(url)
                        break

            for authz in auth_endpoints:
                try:
                    self._check_redirect_uri_wildcard(authz)
                    self._check_state_missing(authz)
                except Exception as exc:
                    self.log.debug(f"  authz {authz}: {exc}")

            try:
                self._check_saml_metadata(base)
            except Exception as exc:
                self.log.debug(f"  saml {base}: {exc}")

        return self.findings
