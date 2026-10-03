"""
S3 (and GCS / Azure Blob) bucket enumeration.

Generates permutations of the target name and probes for publicly listable
or auth-required buckets across three cloud providers.

Status heuristic:
  * HTTP 200 or XML with "ListBucketResult" => bucket exists and is LISTABLE
    (critical - full contents exposed).
  * HTTP 403 or "AccessDenied" => bucket exists but is private
    (medium - information disclosure of bucket name).
  * NoSuchBucket / 404 => bucket does not exist (skip).
"""
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseCheck
from ..models import Finding
from ..utils import run


PERMUTATION_SUFFIXES = [
    "", "-backup", "-backups", "-dev", "-staging", "-prod",
    "-production", "-test", "-tst", "-qa", "-logs", "-log",
    "-data", "-files", "-storage", "-media", "-assets",
    "-public", "-private", "-internal", "-cdn",
    "-images", "-img", "-video", "-videos", "-upload", "-uploads",
    "-admin", "-dashboard", "-reports", "-report",
    "-old", "-new", "-v1", "-v2", "-archive",
]

PERMUTATION_PREFIXES = [
    "", "backup-", "backups-", "dev-", "staging-", "prod-",
    "test-", "qa-", "logs-", "data-", "files-", "media-",
    "assets-", "cdn-", "img-", "upload-", "admin-",
]


class S3BucketCheck(BaseCheck):
    """Generate bucket-name permutations and probe AWS/GCP/Azure."""

    name = "S3 Buckets"
    description = "Enumerate AWS S3, GCS, Azure Blob buckets with target-name permutations"

    MAX_CANDIDATES = 150

    def _name_variants(self) -> list[str]:
        """Build short names from the target: 'example.com' -> ['example']."""
        base = self.target.lower()
        base = re.sub(r"^(www\.)", "", base)
        parts = base.split(".")
        bases: set[str] = set()
        bases.add(parts[0])
        if len(parts) > 1:
            bases.add(parts[0].replace("-", ""))
            bases.add("".join(parts[:-1]))
        bases.add(base.replace(".", "-"))
        bases.add(base.replace(".", ""))
        # Drop very short or very long
        return sorted({b for b in bases if 3 <= len(b) <= 50})

    def _generate_candidates(self) -> list[str]:
        names = self._name_variants()
        cands: set[str] = set()
        for name in names:
            for suffix in PERMUTATION_SUFFIXES:
                cands.add(f"{name}{suffix}")
            for prefix in PERMUTATION_PREFIXES:
                if prefix:
                    cands.add(f"{prefix}{name}")
        # Filter to valid bucket-name charset and length
        clean = []
        for c in cands:
            if 3 <= len(c) <= 63 and re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", c):
                clean.append(c)
        return sorted(clean)[: self.MAX_CANDIDATES]

    def _probe_s3(self, bucket: str) -> dict | None:
        url = f"https://{bucket}.s3.amazonaws.com/"
        return self._probe_url("AWS S3", bucket, url)

    def _probe_gcs(self, bucket: str) -> dict | None:
        url = f"https://storage.googleapis.com/{bucket}/"
        return self._probe_url("GCS", bucket, url)

    def _probe_azure(self, bucket: str) -> dict | None:
        url = f"https://{bucket}.blob.core.windows.net/?comp=list"
        return self._probe_url("Azure Blob", bucket, url)

    def _probe_url(self, provider: str, bucket: str, url: str) -> dict | None:
        rc, body, _ = run(["curl", "-s", "--max-time", "6",
                           "-w", "\n__STATUS__:%{http_code}", url], timeout=10)
        if rc != 0 or not body:
            return None
        m = re.search(r"__STATUS__:(\d+)\s*$", body)
        status = int(m.group(1)) if m else 0
        payload = body[:m.start()] if m else body

        payload_lower = payload.lower()
        if "nosuchbucket" in payload_lower or "containernotfound" in payload_lower:
            return None
        if provider == "GCS" and "nosuchkey" in payload_lower and status == 404:
            return None
        if status == 404 and "<?xml" not in payload_lower and "listbucketresult" not in payload_lower:
            return None

        listable = ("<listbucketresult" in payload_lower or
                    "<enumerationresults" in payload_lower or
                    "<ListBucketResult" in payload or
                    (provider == "GCS" and status == 200 and "<Contents>" in payload))
        access_denied = (status == 403 or
                         "accessdenied" in payload_lower or
                         "all access to this object has been disabled" in payload_lower)

        if listable:
            return {"provider": provider, "bucket": bucket, "url": url,
                    "state": "listable", "status": status}
        if access_denied:
            return {"provider": provider, "bucket": bucket, "url": url,
                    "state": "access-denied", "status": status}
        if status in (200, 206) and payload:
            return {"provider": provider, "bucket": bucket, "url": url,
                    "state": "exists", "status": status}
        return None

    def execute(self) -> list[Finding]:
        candidates = self._generate_candidates()
        self.log.info(f"  S3 buckets: testing {len(candidates)} candidate name(s) "
                      f"across AWS / GCS / Azure")
        probes = []
        for b in candidates:
            probes.append((self._probe_s3, b))
            probes.append((self._probe_gcs, b))
            probes.append((self._probe_azure, b))

        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=min(self.threads, 15)) as ex:
            futures = [ex.submit(fn, b) for fn, b in probes]
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)

        for r in results:
            if r["state"] == "listable":
                sev = "critical"
                title = f"{r['provider']} bucket PUBLIC LIST: {r['bucket']}"
                detail = (f"Bucket '{r['bucket']}' on {r['provider']} is publicly "
                          f"listable at {r['url']} - full contents enumerable")
            elif r["state"] == "access-denied":
                sev = "medium"
                title = f"{r['provider']} bucket exists (private): {r['bucket']}"
                detail = (f"Bucket '{r['bucket']}' on {r['provider']} exists but "
                          f"blocks listing. Name disclosure helps targeted attacks.")
            else:
                sev = "info"
                title = f"{r['provider']} bucket responds: {r['bucket']}"
                detail = (f"Bucket '{r['bucket']}' on {r['provider']} returned "
                          f"status {r['status']}; manual verification recommended.")
            self.findings.append(Finding(
                severity=sev,
                title=title,
                host=r["url"],
                detail=detail,
                source="s3_buckets",
                url=r["url"],
                tags=["cloud-storage", r["provider"].lower().replace(" ", "-"),
                      r["state"]],
                evidence=f"bucket={r['bucket']} status={r['status']}",
            ))
        self.log.info(f"  S3 buckets: {len(results)} candidate(s) responded")
        return self.findings
