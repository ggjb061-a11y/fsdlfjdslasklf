"""
Tests for the dedicated CVE detector plugins.

Each test monkey-patches the detector's _run function to return canned
HTTP responses. Verifies:
  * Positive case: vulnerable response -> CVEResult(vulnerable=True)
  * Negative case: benign response -> None
  * Baseline guard: indicator present in BASELINE -> no false positive
"""
import tempfile
import unittest
from unittest.mock import patch

from scanner.checks.cves import ALL_CVE_DETECTORS
from scanner.utils import create_dirs


def canned_run(responses):
    """Return a fake run() that cycles through canned (rc, body, '')."""
    responses = list(responses)
    idx = [0]
    def _run(cmd, **kwargs):
        if idx[0] >= len(responses):
            return (-1, "", "")
        r = responses[idx[0]]
        idx[0] += 1
        return r
    return _run


def wrap_body(body: str, status: int = 200) -> str:
    """Append the __STATUS__ sentinel the base helper strips."""
    return f"{body}\n__STATUS__:{status}"


class TestRegistryAndMeta(unittest.TestCase):
    def test_at_least_20_detectors(self):
        self.assertGreaterEqual(len(ALL_CVE_DETECTORS), 20)

    def test_all_detectors_have_metadata(self):
        for cls in ALL_CVE_DETECTORS:
            self.assertTrue(cls.cve_id.startswith("CVE-"),
                            f"{cls.__name__} must have cve_id")
            self.assertTrue(cls.title)
            self.assertIn(cls.severity, ("critical", "high", "medium", "low", "info"))
            self.assertTrue(cls.affected)
            self.assertTrue(cls.tags)
            self.assertIn(cls.cve_id.lower(), cls.tags)


class TestApache2449(unittest.TestCase):
    def test_detects_etc_passwd(self):
        from scanner.checks.cves.apache_2449_pt import Apache2449Traversal
        responses = [(0, wrap_body("root:x:0:0:root:/root:/bin/bash\nuser:x:1000"), "")]
        d = Apache2449Traversal(canned_run(responses))
        r = d.probe("https://x.com", "<html>normal</html>")
        self.assertIsNotNone(r)
        self.assertTrue(r.vulnerable)

    def test_no_fp_when_indicator_in_baseline(self):
        from scanner.checks.cves.apache_2449_pt import Apache2449Traversal
        baseline = "<html>Example: root:x:0:0 is the UID 0 entry</html>"
        responses = [(0, wrap_body(baseline), "")] * 10
        d = Apache2449Traversal(canned_run(responses))
        self.assertIsNone(d.probe("https://x.com", baseline))

    def test_no_fp_on_404(self):
        from scanner.checks.cves.apache_2449_pt import Apache2449Traversal
        responses = [(0, wrap_body("<html>404 Not Found</html>", 404), "")] * 10
        d = Apache2449Traversal(canned_run(responses))
        self.assertIsNone(d.probe("https://x.com", "<html>welcome</html>"))


class TestApache2450(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.apache_2450_pt import Apache2450Traversal
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "nobody:x:65534:65534:nobody:/:/sbin/nologin\n")
        d = Apache2450Traversal(canned_run([
            (0, wrap_body(passwd), "")
        ]))
        r = d.probe("https://x", "")
        self.assertIsNotNone(r)


class TestWebLogicWLS(unittest.TestCase):
    def test_detects_endpoint(self):
        from scanner.checks.cves.weblogic_wls_sec import WeblogicWLSSecurity
        d = WeblogicWLSSecurity(canned_run([
            (0, wrap_body("<wsdl>CoordinatorPortType wls-wsat ...</wsdl>"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestWebLogicAsync(unittest.TestCase):
    def test_detects_endpoint(self):
        from scanner.checks.cves.weblogic_async import WeblogicAsyncResponseService
        d = WeblogicAsyncResponseService(canned_run([
            (0, wrap_body("AsyncResponseService SOAP binding"), ""),
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestWebLogicConsole(unittest.TestCase):
    def test_detects_console(self):
        from scanner.checks.cves.weblogic_console import WeblogicConsoleBypass
        d = WeblogicConsoleBypass(canned_run([
            (0, wrap_body("ConsoleHelp wl_console weblogic Console Login"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))

    def test_no_fp_when_baseline_already_shows_login(self):
        from scanner.checks.cves.weblogic_console import WeblogicConsoleBypass
        d = WeblogicConsoleBypass(canned_run([
            (0, wrap_body("ConsoleHelp wl_console weblogic Console Login"), "")
        ]))
        self.assertIsNone(d.probe("https://x", "Console Login was already here"))


class TestF5TMUI(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.f5_tmui import F5TMUI
        d = F5TMUI(canned_run([
            (0, wrap_body("root:x:0:0:root:/root:/bin/bash"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestJBoss(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.jboss_filter import JBossReadOnly
        d = JBossReadOnly(canned_run([
            (0, wrap_body("JBossMQ JBoss ReadOnly", 500), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestElasticsearchGroovy(unittest.TestCase):
    def test_detects_marker(self):
        from scanner.checks.cves.elasticsearch_groovy import ElasticsearchGroovy
        marker = "cveprobe7x7marker"
        d = ElasticsearchGroovy(canned_run([
            (0, wrap_body(f'{{"hits":{{"hits":[{{"fields":{{"test":["{marker}"]}}}}]}}}}'), "")
        ]))
        r = d.probe("https://x", "")
        self.assertIsNotNone(r)


class TestSolr(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.solr_replication import SolrReplicationHandler
        d = SolrReplicationHandler(canned_run([
            (0, wrap_body('{"responseHeader":{"status":0},"cores":{}}'), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestKibana(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.kibana_source import KibanaSource
        d = KibanaSource(canned_run([
            (0, wrap_body('{"name":"kibana","version":"6.5.0"}'), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestCitrixNetScaler(unittest.TestCase):
    def test_detects_smb_conf(self):
        from scanner.checks.cves.citrix_netscaler import CitrixNetScaler
        d = CitrixNetScaler(canned_run([
            (0, wrap_body("[global]\nworkgroup = WORKGROUP\n"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestSpringGateway(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.spring_gateway import SpringCloudGateway
        d = SpringCloudGateway(canned_run([
            (0, wrap_body('[{"predicates":[],"filters":[],"id":"gateway"}]'), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestSpringFunction(unittest.TestCase):
    def test_detects_marker(self):
        from scanner.checks.cves.spring_function import SpringCloudFunction
        marker = "cvespringfn7x7"
        d = SpringCloudFunction(canned_run([
            (0, wrap_body(f"evaluated to {marker}"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestVMwareVCenter(unittest.TestCase):
    def test_detects_405(self):
        from scanner.checks.cves.vmware_vcenter import VMwareVCenter
        d = VMwareVCenter(canned_run([
            (0, wrap_body("Method Not Allowed", 405), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestRailsAccept(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.rails_accept import RailsAccept
        d = RailsAccept(canned_run([
            (0, wrap_body("root:x:0:0:root:/root"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestWSO2(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.wso2_upload import WSO2Upload
        d = WSO2Upload(canned_run([
            (0, wrap_body("WSO2 Carbon fileupload", 405), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestPaperCut(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.papercut_bypass import PaperCutBypass
        d = PaperCutBypass(canned_run([
            (0, wrap_body("PaperCut Setup admin"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestStrutsRest(unittest.TestCase):
    def test_detects(self):
        from scanner.checks.cves.struts_rest import StrutsREST
        d = StrutsREST(canned_run([
            (0, wrap_body("<orders><order></order></orders>"), "")
        ]))
        self.assertIsNotNone(d.probe("https://x", ""))


class TestMegaCheckIntegration(unittest.TestCase):
    def test_megacheck_runs_without_crash_on_empty_responses(self):
        from scanner.checks.cves_check import CVEMegaCheck
        tmp = tempfile.TemporaryDirectory()
        dirs = create_dirs(tmp.name, "example.com")
        try:
            c = CVEMegaCheck(target="example.com", dirs=dirs,
                             live_hosts=["https://example.com"], threads=1)
            with patch("scanner.checks.cves_check.run",
                       return_value=(0, "nothing to see here", "")):
                findings = c.execute()
                self.assertIsInstance(findings, list)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
