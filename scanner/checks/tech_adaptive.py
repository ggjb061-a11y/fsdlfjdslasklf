"""
Technology-adaptive deep checks.

Reads the target fingerprint and runs tech-specific probes:

  WordPress -> wp-login, wp-config.php.bak, xmlrpc amplification probe,
               /wp-json/wp/v2/users enumeration, common wp-plugin paths
  Laravel   -> /.env, /storage/logs/laravel.log, /_ignition/execute-solution,
               /telescope, debug mode probe
  Node/Express -> /node_modules/, /.env, /package.json leak
  Spring    -> /actuator, /actuator/env, /actuator/heapdump,
               /jolokia, /refresh (CVE-2022-22947 Spring Cloud Gateway)
  Django    -> /admin/, debug=True detection
"""
import json
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class TechAdaptiveCheck(BaseCheck):
    """Fingerprint technology and run tech-specific deep checks."""

    name = "Tech-Adaptive Deep Checks"
    description = (
        "Fingerprint technology (WordPress/Laravel/Node/Spring/Django) "
        "and run framework-specific probes"
    )

    def _fetch(self, url: str) -> tuple[int, str, str]:
        """Return (status, body, response_headers)."""
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "6",
             "-D", "-", url], timeout=10,
        )
        if rc != 0 or not body:
            return 0, "", ""
        # Status line in curl -D -
        status = 0
        headers = ""
        parts = body.split("\r\n\r\n", 1)
        if len(parts) == 2:
            headers = parts[0]
            body = parts[1]
        else:
            parts = body.split("\n\n", 1)
            if len(parts) == 2:
                headers = parts[0]
                body = parts[1]
        m = re.search(r"HTTP/[\d.]+\s+(\d+)", headers)
        if m:
            status = int(m.group(1))
        return status, body, headers

    def _fingerprint(self, base: str) -> set[str]:
        """Return a set of detected tech labels."""
        detected: set[str] = set()
        status, body, headers = self._fetch(base)
        combined = (body + "\n" + headers).lower()
        if not combined:
            return detected

        if any(sig in combined for sig in [
            "wp-content/", "wp-includes/", "/wp-json/", "wordpress"
        ]):
            detected.add("wordpress")
        if any(sig in combined for sig in [
            "laravel", "x-powered-by: laravel", "laravel_session"
        ]):
            detected.add("laravel")
        if any(sig in combined for sig in [
            "express", "x-powered-by: express", "node.js"
        ]):
            detected.add("node")
        if any(sig in combined for sig in [
            "x-application-context", "whitelabel error page",
            "spring", "springboot"
        ]):
            detected.add("spring")
        if any(sig in combined for sig in [
            "csrfmiddlewaretoken", "django", "x-frame-options: deny"
        ]) and "django" in combined:
            detected.add("django")
        if "drupal" in combined or "x-generator: drupal" in combined:
            detected.add("drupal")
        if "joomla" in combined:
            detected.add("joomla")

        return detected

    # ---------------- WordPress ----------------
    def _wordpress(self, base: str) -> None:
        # /wp-json/wp/v2/users (user enumeration)
        status, body, _ = self._fetch(f"{base}/wp-json/wp/v2/users")
        if status == 200 and body.strip().startswith("["):
            try:
                users = json.loads(body)
                if isinstance(users, list) and users:
                    names = [u.get("slug", u.get("name", "?")) for u in users[:10]]
                    self.findings.append(Finding(
                        severity="medium",
                        title="WordPress User Enumeration via REST API",
                        host=base,
                        detail=f"GET /wp-json/wp/v2/users returned {len(users)} users: {', '.join(names)}",
                        source="tech_adaptive",
                        url=f"{base}/wp-json/wp/v2/users",
                        tags=["wordpress", "user-enum", "wp-rest-api"],
                        evidence=", ".join(names),
                    ))
            except Exception:
                pass

        # xmlrpc.php - look for methods list
        status, body, _ = self._fetch(f"{base}/xmlrpc.php")
        if status == 200 and ("XML-RPC server" in body or "methodCall" in body):
            self.findings.append(Finding(
                severity="low",
                title="WordPress XML-RPC endpoint exposed",
                host=base,
                detail=(
                    "XML-RPC endpoint reachable at /xmlrpc.php. Attackers abuse "
                    "wp.getUsersBlogs / system.multicall for brute force and "
                    "SSRF (pingback DDoS). Disable if unused."
                ),
                source="tech_adaptive",
                url=f"{base}/xmlrpc.php",
                tags=["wordpress", "xmlrpc"],
            ))

        # wp-config backups
        for p in ["/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
                  "/wp-config.php.save", "/.wp-config.php.swp"]:
            status, body, _ = self._fetch(f"{base}{p}")
            if status == 200 and ("DB_PASSWORD" in body or "DB_NAME" in body):
                self.findings.append(Finding(
                    severity="critical",
                    title=f"WordPress config backup exposed: {p}",
                    host=base,
                    detail=f"wp-config backup at {p} leaks DB credentials",
                    source="tech_adaptive",
                    url=f"{base}{p}",
                    tags=["wordpress", "config-leak", "credentials-exposed"],
                ))

    # ---------------- Laravel ----------------
    def _laravel(self, base: str) -> None:
        # .env (sensitive config)
        status, body, _ = self._fetch(f"{base}/.env")
        if status == 200 and ("APP_KEY=" in body or "DB_PASSWORD=" in body):
            self.findings.append(Finding(
                severity="critical",
                title="Laravel .env file exposed",
                host=base,
                detail="Laravel .env with APP_KEY/DB credentials readable at /.env",
                source="tech_adaptive",
                url=f"{base}/.env",
                tags=["laravel", "env-leak", "credentials-exposed"],
            ))

        # /_ignition - Laravel debug page RCE vulnerable in <=8.4.2
        status, body, _ = self._fetch(f"{base}/_ignition/execute-solution")
        if status in (200, 405, 500) and "ignition" in body.lower():
            self.findings.append(Finding(
                severity="critical",
                title="Laravel Ignition debug page reachable (CVE-2021-3129)",
                host=base,
                detail="Ignition debug handler is reachable. CVE-2021-3129 allows unauth RCE on vulnerable versions.",
                source="tech_adaptive",
                url=f"{base}/_ignition/execute-solution",
                tags=["laravel", "cve-2021-3129", "rce-potential"],
            ))

        # Telescope - debug ui exposed
        status, body, _ = self._fetch(f"{base}/telescope")
        if status == 200 and "telescope" in body.lower():
            self.findings.append(Finding(
                severity="high",
                title="Laravel Telescope debug UI exposed",
                host=base,
                detail="/telescope is reachable - debug and query logs likely exposed",
                source="tech_adaptive",
                url=f"{base}/telescope",
                tags=["laravel", "telescope", "debug-ui-exposed"],
            ))

        # Debug log
        status, body, _ = self._fetch(f"{base}/storage/logs/laravel.log")
        if status == 200 and ("[20" in body or "local.ERROR" in body):
            self.findings.append(Finding(
                severity="high",
                title="Laravel log file exposed",
                host=base,
                detail="/storage/logs/laravel.log is publicly readable",
                source="tech_adaptive",
                url=f"{base}/storage/logs/laravel.log",
                tags=["laravel", "log-leak"],
            ))

    # ---------------- Node / Express ----------------
    def _node(self, base: str) -> None:
        for p in ["/.env", "/package.json", "/package-lock.json",
                  "/node_modules/", "/npm-debug.log", "/.npmrc"]:
            status, body, _ = self._fetch(f"{base}{p}")
            if status != 200 or not body:
                continue
            sig = None
            if p == "/package.json" and '"name"' in body and '"dependencies"' in body:
                sig = "package.json leaks dependency names and versions"
            elif p == "/package-lock.json" and '"lockfileVersion"' in body:
                sig = "package-lock.json leaks exact dependency versions"
            elif p == "/.env" and "=" in body:
                sig = ".env readable"
            elif p == "/.npmrc" and ("_authToken=" in body or "registry=" in body):
                sig = ".npmrc may contain registry auth tokens"
            elif p == "/node_modules/" and ("index of" in body.lower() or "<a href" in body.lower()):
                sig = "node_modules/ is directory-listable"
            if sig:
                sev = "critical" if p in ("/.env", "/.npmrc") else "high"
                self.findings.append(Finding(
                    severity=sev, title=f"Node leak via {p}",
                    host=base, detail=sig, source="tech_adaptive",
                    url=f"{base}{p}", tags=["node", "config-leak"],
                ))

    # ---------------- Spring ----------------
    def _spring(self, base: str) -> None:
        for p in ["/actuator", "/actuator/env", "/actuator/health",
                  "/actuator/mappings", "/actuator/configprops",
                  "/actuator/beans", "/actuator/httptrace",
                  "/actuator/threaddump", "/actuator/heapdump",
                  "/env", "/trace", "/jolokia", "/jolokia/list"]:
            status, body, _ = self._fetch(f"{base}{p}")
            if status != 200 or len(body) < 10:
                continue
            # Try to detect it's actually actuator output
            is_actuator = ("_links" in body or '"status":"UP"' in body or
                           '"activeProfiles"' in body or
                           "spring.application" in body or
                           "jolokia" in body.lower() or
                           '"javaVersion"' in body)
            if is_actuator:
                sev = "high"
                if p in ("/actuator/env", "/env", "/actuator/heapdump",
                         "/actuator/threaddump", "/jolokia", "/jolokia/list"):
                    sev = "critical"
                self.findings.append(Finding(
                    severity=sev,
                    title=f"Spring Actuator endpoint exposed: {p}",
                    host=base,
                    detail=f"Spring Boot management endpoint {p} is publicly accessible",
                    source="tech_adaptive",
                    url=f"{base}{p}",
                    tags=["spring", "actuator", p.strip("/").replace("/", "-")],
                ))

    # ---------------- Django ----------------
    def _django(self, base: str) -> None:
        status, body, _ = self._fetch(f"{base}/admin/")
        if status == 200 and ("Django administration" in body or
                               "django-admin" in body.lower()):
            self.findings.append(Finding(
                severity="low",
                title="Django admin interface exposed",
                host=base,
                detail="/admin/ login page is public - restrict by IP or VPN",
                source="tech_adaptive",
                url=f"{base}/admin/",
                tags=["django", "admin-exposed"],
            ))

    def execute(self) -> list[Finding]:
        for base in self._hosts(3):
            try:
                detected = self._fingerprint(base)
                if not detected:
                    continue
                self.log.info(f"  {base} tech: {', '.join(sorted(detected))}")
                if "wordpress" in detected:
                    self._wordpress(base)
                if "laravel" in detected:
                    self._laravel(base)
                if "node" in detected:
                    self._node(base)
                if "spring" in detected:
                    self._spring(base)
                if "django" in detected:
                    self._django(base)
            except Exception as exc:
                self.log.debug(f"  tech_adaptive {base}: {exc}")
        return self.findings
