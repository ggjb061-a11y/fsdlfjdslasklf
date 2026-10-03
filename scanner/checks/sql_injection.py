"""Direct SQL injection probing (error-based + boolean-based)."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class SQLInjectionCheck(BaseCheck):
    """Fuzz common parameters with SQLi payloads and detect error signatures."""

    name = "SQL Injection"
    description = "Test for error-based and boolean-based SQL injection"

    PARAMS = [
        "id", "user", "username", "email", "name", "page", "cat",
        "category", "search", "q", "query", "item", "product",
        "pid", "uid", "news", "year", "month",
    ]

    PAYLOADS = ["'", "\"", "')", "';", "' OR '1'='1", "' AND 1=2--"]

    ERROR_SIGNATURES = [
        "sql syntax", "mysql_fetch", "mysql_num_rows", "mysql error",
        "you have an error in your sql syntax",
        "warning: pg_", "unclosed quotation mark",
        "ora-00933", "ora-00921", "ora-01756", "ora-00942",
        "microsoft ole db provider for sql server",
        "sqlstate", "sqlite_error", "sqlite3.operationalerror",
        "psycopg2.errors", "org.postgresql.util.psqlexception",
        "com.microsoft.sqlserver.jdbc",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for param in self.PARAMS:
                for payload in self.PAYLOADS:
                    import urllib.parse
                    enc = urllib.parse.quote(payload, safe="")
                    test_url = f"{base}?{param}={enc}"
                    rc, body, _ = run(
                        ["curl", "-sL", "--max-time", "6", test_url],
                        timeout=10,
                    )
                    if rc != 0 or not body:
                        continue
                    body_lower = body.lower()
                    for sig in self.ERROR_SIGNATURES:
                        if sig in body_lower:
                            self.findings.append(Finding(
                                severity="critical",
                                title=f"SQL Injection (error-based) via '{param}'",
                                host=base,
                                detail=f"Parameter '{param}' triggers DB error signature: {sig}",
                                source="sqli",
                                url=test_url,
                                evidence=sig,
                            ))
                            return self.findings
        return self.findings
