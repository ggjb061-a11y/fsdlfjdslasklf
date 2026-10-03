"""Swagger / OpenAPI endpoint discovery."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class SwaggerCheck(BaseCheck):
    name = "Swagger/OpenAPI"
    description = "Discover exposed API documentation endpoints"

    API_PATHS = [
        "/swagger.json", "/swagger/v1/swagger.json",
        "/api-docs", "/api-docs.json",
        "/openapi.json", "/openapi.yaml",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/swagger-ui.html", "/swagger-ui/",
        "/api/swagger.json", "/api/openapi.json",
        "/docs", "/redoc", "/api/docs",
        "/.well-known/openapi.yaml",
        "/api/schema", "/schema.json",
        "/swagger-resources",
        "/api/v1/swagger.json", "/api/v2/swagger.json",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for path in self.API_PATHS:
                url = f"{base}{path}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "5", url],
                    timeout=8,
                )
                if rc != 0 or not out:
                    continue
                first_line = out.splitlines()[0] if out.splitlines() else ""
                if self._status_code(first_line) != 200:
                    continue

                ct = ""
                for line in out.splitlines():
                    if line.lower().startswith("content-type:"):
                        ct = line.split(":", 1)[1].strip().lower()

                is_api_doc = any(x in ct for x in ["json", "yaml", "html"])
                if is_api_doc or "swagger" in path or "openapi" in path or "api-docs" in path:
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"API Documentation Exposed: {path}",
                        host=base,
                        detail=f"API documentation publicly accessible at {url}",
                        source="swagger_discovery",
                        url=url,
                    ))

        return self.findings
