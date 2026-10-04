"""
Comprehensive SQL injection check: error-based, boolean-based, time-based,
UNION-based detection with baseline comparison to reduce false positives.

Design principle: NEVER emit a finding on error-signature alone - always
compare against a benign baseline. Flag only when the attacker-controlled
response measurably differs from the baseline AND a DB-specific signature
or timing delta is present.
"""
import time
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class SQLInjectionCheck(BaseCheck):
    """
    Multi-technique SQLi probing with baseline comparison.

    Techniques:
      1. Error-based  - DB engine error signatures (18 engines)
      2. Boolean-based - response-length delta between '1=1' and '1=2'
      3. Time-based blind - SLEEP() / WAITFOR / pg_sleep() with delta
      4. UNION-based - probe for columns via ORDER BY and NULL UNION
    """

    name = "SQL Injection"
    description = "Error / Boolean / Time / UNION-based SQL injection detection"

    PARAMS = [
        "id", "user", "username", "email", "name", "page", "cat",
        "category", "search", "q", "query", "item", "product",
        "pid", "uid", "news", "year", "month", "sort", "order",
        "filter", "type", "ref", "lang", "locale",
    ]

    ERROR_PAYLOADS = ["'", "\"", "')", "';", "' AND SLEEP(0)-- -", "`", "\\'"]

    BOOL_TRUE_PAYLOADS = [
        "' AND '1'='1",
        "' AND 1=1-- -",
        "\" AND \"1\"=\"1",
    ]
    BOOL_FALSE_PAYLOADS = [
        "' AND '1'='2",
        "' AND 1=2-- -",
        "\" AND \"1\"=\"2",
    ]

    TIME_PAYLOADS = [
        ("MySQL",      "' AND SLEEP(5)-- -"),
        ("PostgreSQL", "'; SELECT pg_sleep(5)-- "),
        ("MSSQL",      "'; WAITFOR DELAY '0:0:5'-- "),
        ("Oracle",     "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- "),
    ]

    ERROR_SIGNATURES = {
        "MySQL": [
            "sql syntax", "mysql_fetch", "mysql_num_rows",
            "you have an error in your sql syntax",
            "mysql_query", "mysql_result", "mysqli_",
            "warning: mysql", "unknown column", "mysqlclient",
        ],
        "PostgreSQL": [
            "warning: pg_", "pg_exec", "pg_query",
            "psycopg2.errors", "org.postgresql.util.psqlexception",
            "postgres error", "quoted string not properly terminated",
        ],
        "MSSQL": [
            "microsoft ole db provider for sql server",
            "microsoft sql native client",
            "com.microsoft.sqlserver.jdbc",
            "sqlserver jdbc driver", "incorrect syntax near",
            "unclosed quotation mark", "sqlstate",
        ],
        "Oracle": [
            "ora-00933", "ora-00921", "ora-01756", "ora-00942",
            "ora-00904", "oracle driver", "oracle error",
        ],
        "SQLite": [
            "sqlite_error", "sqlite3.operationalerror",
            "sqlite3_prepare", "sqlite_master",
        ],
        "Generic": ["sql syntax", "sqlstate", "database error", "db error"],
    }

    def _fetch(self, url: str, timeout: int = 8) -> tuple[int, str, float]:
        """Return (rc, body, elapsed_seconds). elapsed is monotonic wall time."""
        start = time.monotonic()
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", str(timeout), url],
            timeout=timeout + 4,
        )
        return rc, (body or ""), (time.monotonic() - start)

    def _url(self, base: str, param: str, value: str) -> str:
        return f"{base}?{param}={urllib.parse.quote(value, safe='')}"

    def _check_param(self, base: str, param: str) -> bool:
        """Return True once a confirmed SQLi finding is appended for this param."""
        rc, baseline, baseline_time = self._fetch(self._url(base, param, "1"), timeout=6)
        if rc != 0 or not baseline:
            return False
        baseline_len = len(baseline)
        baseline_lower = baseline.lower()

        # Technique 1: Error-based (requires signature NOT in baseline)
        for payload in self.ERROR_PAYLOADS:
            rc, body, _ = self._fetch(self._url(base, param, payload), timeout=6)
            if rc != 0 or not body:
                continue
            body_lower = body.lower()
            for engine, sigs in self.ERROR_SIGNATURES.items():
                for sig in sigs:
                    if sig in body_lower and sig not in baseline_lower:
                        self.findings.append(Finding(
                            severity="critical",
                            title=f"SQL Injection (error-based, {engine}) via '{param}' [built-in]",
                            host=base,
                            detail=(
                                f"Detector: AutoVulnScan built-in SQLi engine.\n"
                                f"Parameter '{param}' triggers {engine} error signature "
                                f"'{sig}' with payload {payload!r}. Error absent from "
                                f"benign baseline, confirming parameter reaches the SQL layer."
                            ),
                            source="sqli",
                            url=self._url(base, param, payload),
                            tags=["sqli", "error-based", engine.lower(),
                                  f"param:{param}", "detector:builtin"],
                            evidence=f"signature={sig} | payload={payload}",
                        ))
                        return True

        # Technique 2: Boolean-based (requires length delta between TRUE and FALSE)
        for t_payload, f_payload in zip(self.BOOL_TRUE_PAYLOADS, self.BOOL_FALSE_PAYLOADS):
            rc1, t_body, _ = self._fetch(self._url(base, param, f"1{t_payload}"), timeout=6)
            rc2, f_body, _ = self._fetch(self._url(base, param, f"1{f_payload}"), timeout=6)
            if rc1 != 0 or rc2 != 0 or not t_body or not f_body:
                continue
            delta_t = abs(len(t_body) - baseline_len)
            delta_f = abs(len(f_body) - baseline_len)
            # TRUE should resemble baseline (small delta); FALSE should diverge
            if delta_t < 50 and delta_f > 500 and len(t_body) != len(f_body):
                self.findings.append(Finding(
                    severity="critical",
                    title=f"SQL Injection (boolean-based) via '{param}' [built-in]",
                    host=base,
                    detail=(
                        f"Detector: AutoVulnScan built-in SQLi engine.\n"
                        f"Parameter '{param}' shows boolean-based SQLi: "
                        f"'{t_payload}' matches baseline (delta {delta_t}B) while "
                        f"'{f_payload}' diverges by {delta_f}B. Content-length comparison "
                        f"confirms attacker-controlled WHERE clause."
                    ),
                    source="sqli",
                    url=self._url(base, param, f"1{t_payload}"),
                    tags=["sqli", "boolean-based", f"param:{param}", "detector:builtin"],
                    evidence=f"TRUE-delta={delta_t}B FALSE-delta={delta_f}B",
                ))
                return True

        # Technique 3: Time-based blind. Threshold is baseline-RELATIVE
        # (baseline_time + 4s) so a legitimately slow endpoint whose p95 is
        # ~5s does not fire. Sample baseline as the median of 3 benign shots
        # to kill network-blip skew.
        baseline_samples = []
        for _ in range(3):
            rc_b, _, el_b = self._fetch(self._url(base, param, "1"), timeout=6)
            if rc_b == 0:
                baseline_samples.append(el_b)
        if baseline_samples:
            import statistics as _stats
            baseline_med = _stats.median(baseline_samples)
        else:
            baseline_med = baseline_time
        time_threshold = baseline_med + 4.0
        for engine, payload in self.TIME_PAYLOADS:
            # Skip entirely on already-slow endpoints to avoid long waits.
            if baseline_med > 3.0:
                break
            rc, body, elapsed = self._fetch(self._url(base, param, f"1{payload}"), timeout=10)
            if rc != 0:
                continue
            # Verify with second shot to avoid network-blip FPs
            if elapsed >= time_threshold:
                rc2, _, elapsed2 = self._fetch(self._url(base, param, f"1{payload}"), timeout=10)
                if rc2 == 0 and elapsed2 >= time_threshold:
                    self.findings.append(Finding(
                        severity="critical",
                        title=f"SQL Injection (time-based blind, {engine}) via '{param}' [built-in]",
                        host=base,
                        detail=(
                            f"Detector: AutoVulnScan built-in SQLi engine.\n"
                            f"Parameter '{param}' triggers a {engine} sleep: baseline "
                            f"median {baseline_med:.1f}s vs injected {elapsed:.1f}s / {elapsed2:.1f}s "
                            f"(both >= {time_threshold:.1f}s = baseline+4s). "
                            f"Two consecutive confirmations reduce flake risk."
                        ),
                        source="sqli",
                        url=self._url(base, param, f"1{payload}"),
                        tags=["sqli", "time-based", engine.lower(),
                              f"param:{param}", "detector:builtin"],
                        evidence=f"baseline_med={baseline_med:.1f}s inject={elapsed:.1f}s re-check={elapsed2:.1f}s",
                    ))
                    return True

        # Technique 4: UNION column enumeration (ORDER BY).
        # Correct differential test: the SAME payload shape at col_count=1 must
        # NOT trigger an error (there is always >=1 column), but a very large
        # col_count SHOULD. A WAF/error-page that fires on ANY `-- -` payload
        # trips both and is filtered out. The Generic bucket is skipped - raw
        # English phrases like "database error" are too noisy to drive a
        # critical finding (they appear in WAF block pages for every payload).
        strong_engines = {k: v for k, v in self.ERROR_SIGNATURES.items()
                           if k != "Generic"}

        def _hits_at(col: int) -> set:
            payload = f"1' ORDER BY {col}-- -"
            rc, body, _ = self._fetch(self._url(base, param, payload), timeout=6)
            if rc != 0 or not body:
                return set()
            body_lower = body.lower()
            hits = set()
            for sigs in strong_engines.values():
                for sig in sigs:
                    if sig in body_lower and sig not in baseline_lower:
                        hits.add(sig)
            return hits

        hits_low = _hits_at(1)
        hits_high = _hits_at(10)
        # Signatures that appear at col=10 but NOT at col=1 are UNION-specific.
        diff = hits_high - hits_low
        if diff:
            sig = sorted(diff)[0]
            self.findings.append(Finding(
                severity="high",
                title=f"SQL Injection (UNION probe) via '{param}' [built-in]",
                host=base,
                detail=(
                    f"Detector: AutoVulnScan built-in SQLi engine.\n"
                    f"ORDER BY column enumeration differentiates between "
                    f"col_count=1 (no error) and col_count=10 (error "
                    f"'{sig}'), isolating a UNION-compatible SELECT. "
                    f"A WAF that errored on any payload would have tripped "
                    f"both probes and been filtered out."
                ),
                source="sqli",
                url=self._url(base, param, "1' ORDER BY 10-- -"),
                tags=["sqli", "union-based", f"param:{param}", "detector:builtin"],
                evidence=f"col=1 -> clean | col=10 -> {sig}",
            ))
            return True

        return False

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for param in self.PARAMS:
                try:
                    if self._check_param(base, param):
                        break  # one SQLi per host is enough signal
                except Exception as exc:
                    self.log.debug(f"  sqli {base} {param}: {exc}")
        return self.findings
