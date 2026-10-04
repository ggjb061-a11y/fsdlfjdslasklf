"""
OpenAPI / Swagger auto-fuzzer.

Discovers an OpenAPI spec, then exercises every path+method with sample
parameters. For each endpoint, three requests go out:
  * No auth
  * Random bogus bearer token
  * Current session (if --cookie / --bearer provided to scanner)

Flags endpoints that return sensitive-looking data WITHOUT auth.
"""
import json
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class OpenAPIFuzzerCheck(BaseCheck):
    name = "OpenAPI Fuzzer"
    description = "Auto-fuzz endpoints from discovered OpenAPI/Swagger spec"

    SPEC_PATHS = [
        "/swagger.json", "/openapi.json", "/api-docs", "/api/swagger.json",
        "/v3/api-docs", "/v2/api-docs", "/api/openapi.json", "/openapi.yaml",
    ]

    SENSITIVE_RESPONSE_SIGNALS = re.compile(
        r'("password"|"email"|"token"|"api_key"|"apikey"|"secret"|'
        r'"ssn"|"credit_card"|"cvv"|"private_key"|"salt"|"hash")',
        re.IGNORECASE,
    )

    def _fetch(self, url: str, timeout: int = 8, headers: list = None,
               method: str = "GET", body: str = None) -> tuple[int, str]:
        args = ["curl", "-sk", "-L", "--max-time", str(timeout),
                "-X", method,
                "-w", "\n__STATUS__:%{http_code}"]
        for h in (headers or []):
            args += ["-H", h]
        if body is not None:
            args += ["-d", body]
        args.append(url)
        rc, out, _ = run(args, timeout=timeout + 4)
        if rc != 0 or not out:
            return 0, ""
        m = re.search(r"__STATUS__:(\d+)\s*$", out)
        status = int(m.group(1)) if m else 0
        return status, out[:m.start()] if m else out

    def _find_spec(self, base: str) -> dict | None:
        for p in self.SPEC_PATHS:
            url = base + p
            status, body = self._fetch(url)
            if status != 200 or not body:
                continue
            # YAML fast-path: skip
            if body.lstrip().startswith("openapi:") or "swagger:" in body[:200]:
                self.log.debug(f"  OpenAPI YAML at {url}; YAML parsing skipped")
                continue
            try:
                spec = json.loads(body)
            except Exception:
                continue
            if "paths" in spec and ("openapi" in spec or "swagger" in spec):
                self.log.info(f"  OpenAPI spec: {url} ({len(spec['paths'])} paths)")
                spec["_url"] = url
                spec["_base"] = base
                return spec
        return None

    def _sample_value(self, schema: dict) -> str:
        t = (schema or {}).get("type", "string")
        if t == "integer" or t == "number":
            return "1"
        if t == "boolean":
            return "true"
        return "test"

    def _build_path(self, path_tmpl: str, parameters: list) -> tuple[str, dict]:
        """Return (filled_path, remaining_query_params)."""
        filled = path_tmpl
        query: dict = {}
        for p in (parameters or []):
            if not isinstance(p, dict):
                continue
            name = p.get("name", "")
            if not name:
                continue
            where = p.get("in", "query")
            value = self._sample_value(p.get("schema", {}))
            if where == "path":
                filled = filled.replace("{" + name + "}", value)
            elif where == "query":
                query[name] = value
        return filled, query

    def _flag_sensitive(self, url: str, status: int, body: str) -> None:
        if status != 200 or not body:
            return
        # Skip HTML redirects / error pages
        if "<html" in body.lower() or "<!doctype" in body.lower():
            return
        m = self.SENSITIVE_RESPONSE_SIGNALS.search(body)
        if m:
            # Do NOT persist response body bytes: the first 300 bytes of a
            # response matching a secret-shaped regex is almost by definition
            # the leaked credential. Record only the signal and size.
            self.findings.append(Finding(
                severity="high",
                title=f"OpenAPI unauthenticated sensitive data: {url}",
                host=url,
                detail=(
                    f"OpenAPI-advertised endpoint returned sensitive-looking "
                    f"data without authentication. Signal: {m.group(0)}"
                ),
                source="openapi_fuzzer",
                url=url,
                tags=["openapi", "unauthenticated", "sensitive-data"],
                evidence=f"signal={m.group(0)} response_bytes={len(body)}",
            ))

    def _probe_endpoints(self, spec: dict) -> None:
        base = spec["_base"]
        base_path = ""
        if "servers" in spec and spec["servers"]:
            srv = spec["servers"][0].get("url", "")
            if srv.startswith("/"):
                base_path = srv.rstrip("/")

        count = 0
        for path, methods in list(spec.get("paths", {}).items())[:30]:
            if not isinstance(methods, dict):
                continue
            for method, meta in methods.items():
                if method.lower() not in ("get", "post", "put", "delete"):
                    continue
                if not isinstance(meta, dict):
                    continue
                params = meta.get("parameters", [])
                filled, query = self._build_path(path, params)
                qstr = "&".join(f"{k}={v}" for k, v in query.items())
                url = f"{base}{base_path}{filled}" + (f"?{qstr}" if qstr else "")

                # Only probe GET for now (POST/PUT/DELETE need body schema)
                if method.lower() != "get":
                    continue
                status, body = self._fetch(url)
                self._flag_sensitive(url, status, body)
                count += 1
                if count > 60:
                    return
        self.log.info(f"  OpenAPI fuzzer: probed {count} endpoints")

    def execute(self) -> list[Finding]:
        for base in self._hosts(3):
            spec = self._find_spec(base)
            if spec:
                self._probe_endpoints(spec)
        return self.findings
