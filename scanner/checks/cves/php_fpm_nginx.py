"""CVE-2019-11043 - PHP-FPM + nginx misconfig buffer underflow."""
from .base import CVEDetector, CVEResult


class PhpFpmNginx(CVEDetector):
    cve_id = "CVE-2019-11043"
    title = "PHP-FPM env_path_info Underflow (reachable PHP path)"
    severity = "high"
    affected = "PHP 7.x FPM behind nginx with specific location+fastcgi_split_path_info"
    tags = ["cve-2019-11043", "php-fpm", "nginx", "rce-potential"]

    def probe(self, base, baseline_body):
        # Vulnerable patterns: a PHP endpoint that reflects env in error
        # We only flag presence of PHP + FPM behind nginx (version detection)
        status, body = self._get(base + "/index.php?a=" + "A" * 2000, timeout=6)
        if not body:
            return None
        headers_hint = "x-powered-by: php" in body.lower() or ".php" in body.lower()
        if headers_hint:
            # Check for nginx header
            status2, hdrs = self._get(base + "/", timeout=6,
                                       extra_args=["-I"])
            if hdrs and ("nginx" in hdrs.lower() and "php" in body.lower()):
                return CVEResult(
                    vulnerable=True,
                    url=base + "/index.php",
                    evidence="PHP backing with nginx front detected",
                    detail=(
                        "PHP + nginx stack identified. If fastcgi_split_path_info "
                        "regex misses, CVE-2019-11043 (PHP-FPM env_path_info "
                        "underflow) enables RCE. Manually confirm fpm config."
                    ),
                )
        return None
