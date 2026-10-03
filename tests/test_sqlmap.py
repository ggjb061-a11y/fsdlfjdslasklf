"""Tests for sqlmap integration (parser + candidate URL builder)."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.checks.sqlmap_scan import SqlmapCheck
from scanner.utils import create_dirs


SQLMAP_SAMPLE_OUTPUT = """
[20:12:33] [INFO] GET parameter 'id' is 'Generic UNION query (NULL)' injectable

sqlmap identified the following injection point(s) with a total of 95 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 2345 FROM (SELECT(SLEEP(5)))abcd)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-1 UNION ALL SELECT NULL,CONCAT(0x717a7a6b71,0x,0x716a7a6271),NULL-- -
---
[20:14:01] [INFO] the back-end DBMS is MySQL
"""


class TestSqlmapParser(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dirs = create_dirs(self._tmp.name, "example.com")
        self.check = SqlmapCheck(
            target="example.com",
            dirs=self.dirs,
            live_hosts=["https://example.com"],
            threads=1,
        )

    def test_parse_extracts_three_techniques(self):
        injections = self.check._parse_sqlmap_output(
            SQLMAP_SAMPLE_OUTPUT, "https://example.com/?id=1"
        )
        types = {i["type"].split()[0] for i in injections}
        self.assertIn("boolean-based", types)
        self.assertIn("time-based", types)
        self.assertIn("UNION", types)
        for inj in injections:
            self.assertEqual(inj["parameter"], "id")

    def test_parse_empty_text(self):
        self.assertEqual(self.check._parse_sqlmap_output("", "https://x/?a=1"), [])

    def test_parse_no_parameter_section(self):
        self.assertEqual(
            self.check._parse_sqlmap_output("Random log line\nnothing of interest", "x"),
            [],
        )


class TestSqlmapCandidates(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dirs = create_dirs(self._tmp.name, "example.com")

    def test_candidates_from_live_hosts(self):
        check = SqlmapCheck(
            target="example.com",
            dirs=self.dirs,
            live_hosts=["https://example.com", "https://api.example.com"],
            threads=1,
        )
        urls = check._candidate_urls()
        self.assertTrue(any("example.com" in u and "?id=1" in u for u in urls))

    def test_candidates_include_discovered_urls(self):
        urls_file = Path(f"{self.dirs['urls']}/all_urls_with_status.txt")
        urls_file.write_text(
            "https://example.com/product?pid=42 200\n"
            "https://example.com/css/style.css 200\n"
        )
        check = SqlmapCheck(
            target="example.com",
            dirs=self.dirs,
            live_hosts=["https://example.com"],
            threads=1,
        )
        urls = check._candidate_urls()
        self.assertTrue(any("pid=42" in u for u in urls))
        self.assertFalse(any("style.css" in u for u in urls))

    def test_candidate_cap(self):
        urls_file = Path(f"{self.dirs['urls']}/all_urls_with_status.txt")
        urls_file.write_text(
            "\n".join(f"https://example.com/x?id={i} 200" for i in range(100))
        )
        check = SqlmapCheck(
            target="example.com",
            dirs=self.dirs,
            live_hosts=["https://example.com"],
            threads=1,
        )
        urls = check._candidate_urls()
        self.assertLessEqual(len(urls), 15)


class TestSqlmapNoBinarySkips(unittest.TestCase):
    def test_execute_without_sqlmap_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            check = SqlmapCheck(
                target="example.com",
                dirs=dirs,
                live_hosts=["https://example.com"],
                threads=1,
            )
            with patch.object(check, "_sqlmap_bin", return_value=None):
                self.assertEqual(check.execute(), [])


class TestSqlmapFindingShape(unittest.TestCase):
    def test_finding_created_from_parsed_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            check = SqlmapCheck(
                target="example.com",
                dirs=dirs,
                live_hosts=["https://example.com"],
                threads=1,
            )
            with patch.object(check, "_sqlmap_bin", return_value="/usr/bin/sqlmap"), \
                 patch.object(check, "_candidate_urls",
                              return_value=["https://example.com/?id=1"]), \
                 patch.object(check, "_run_sqlmap_on_url",
                              return_value=[{
                                  "parameter": "id",
                                  "type": "time-based blind",
                                  "title": "AND time-based blind (SLEEP)",
                                  "payload": "id=1 AND SLEEP(5)",
                                  "url": "https://example.com/?id=1",
                              }]):
                findings = check.execute()
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "critical")
                self.assertIn("sqlmap", findings[0].source)
                self.assertIn("sqlmap", findings[0].tags)
                self.assertIn("confirmed", findings[0].tags)
                self.assertIn("time-based", findings[0].tags)


class TestSQLiDualConfirmationCorrelator(unittest.TestCase):
    """Verify VulnScanner._correlate_sqli emits DUAL-CONFIRMED when both
    the built-in SQLi engine and sqlmap flag the same (host, param)."""

    def _vs(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            from scanner.vulnscan import VulnScanner
            vs = VulnScanner(target="example.com", dirs=dirs,
                             live_hosts=["https://example.com"], threads=1)
            return vs

    def test_dual_confirmation_emits_merged_finding(self):
        from scanner.models import Finding
        vs = self._vs()
        vs.findings = [
            Finding(
                severity="critical",
                title="SQL Injection (error-based, MySQL) via 'id' [built-in]",
                host="https://example.com",
                detail="d1", source="sqli",
                url="https://example.com/?id=',",
                tags=["sqli", "error-based", "mysql", "param:id", "detector:builtin"],
                evidence="signature=mysql_fetch",
            ),
            Finding(
                severity="critical",
                title="SQL Injection (time-based) via 'id' [sqlmap]",
                host="https://example.com/?id=1",
                detail="d2", source="sqlmap",
                url="https://example.com/?id=1",
                tags=["sqli", "sqlmap", "time-based", "param:id", "detector:sqlmap"],
                evidence="Payload: id=1 AND SLEEP(5)",
            ),
        ]
        vs._correlate_sqli()
        dual = [f for f in vs.findings if "DUAL-CONFIRMED" in f.title]
        self.assertEqual(len(dual), 1)
        self.assertEqual(dual[0].source, "correlator")
        self.assertIn("dual-confirmed", dual[0].tags)
        self.assertIn("high-confidence", dual[0].tags)
        self.assertIn("param:id", dual[0].tags)
        # built-in + sqlmap evidence are both carried
        self.assertIn("built-in evidence:", dual[0].evidence)
        self.assertIn("sqlmap evidence:", dual[0].evidence)

    def test_builtin_only_does_not_emit_dual(self):
        from scanner.models import Finding
        vs = self._vs()
        vs.findings = [
            Finding(
                severity="critical",
                title="SQL Injection via 'id' [built-in]",
                host="https://example.com",
                detail="d", source="sqli", url="https://example.com/?id=1",
                tags=["sqli", "param:id", "detector:builtin"],
                evidence="x",
            ),
        ]
        before = len(vs.findings)
        vs._correlate_sqli()
        # No DUAL added because sqlmap didn't confirm
        self.assertFalse(any("DUAL-CONFIRMED" in f.title for f in vs.findings))
        self.assertEqual(len(vs.findings), before)

    def test_sqlmap_only_does_not_emit_dual(self):
        from scanner.models import Finding
        vs = self._vs()
        vs.findings = [
            Finding(
                severity="critical",
                title="SQL Injection via 'id' [sqlmap]",
                host="https://example.com/?id=1",
                detail="d", source="sqlmap", url="https://example.com/?id=1",
                tags=["sqli", "sqlmap", "param:id", "detector:sqlmap"],
                evidence="payload",
            ),
        ]
        vs._correlate_sqli()
        self.assertFalse(any("DUAL-CONFIRMED" in f.title for f in vs.findings))

    def test_different_param_no_dual(self):
        """Same host but different params - must not merge into one DUAL."""
        from scanner.models import Finding
        vs = self._vs()
        vs.findings = [
            Finding(
                severity="critical", title="x [built-in]", host="https://example.com",
                detail="d", source="sqli", url="x",
                tags=["sqli", "param:id", "detector:builtin"], evidence="e",
            ),
            Finding(
                severity="critical", title="x [sqlmap]", host="https://example.com",
                detail="d", source="sqlmap", url="x",
                tags=["sqli", "sqlmap", "param:other", "detector:sqlmap"], evidence="e",
            ),
        ]
        vs._correlate_sqli()
        self.assertFalse(any("DUAL-CONFIRMED" in f.title for f in vs.findings))


if __name__ == "__main__":
    unittest.main()
