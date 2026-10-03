"""CVE-2021-27905 - Apache Solr Replication Handler SSRF->RCE."""
from .base import CVEDetector, CVEResult


class SolrReplicationHandler(CVEDetector):
    cve_id = "CVE-2021-27905"
    title = "Apache Solr Replication Handler SSRF (endpoint reachable)"
    severity = "high"
    affected = "Apache Solr prior to 8.8.2"
    tags = ["cve-2021-27905", "solr", "ssrf"]

    def probe(self, base, baseline_body):
        # Just enumerate cores first
        status, body = self._get(base + "/solr/admin/cores?indexInfo=false&wt=json",
                                   timeout=8)
        if not body:
            return None
        if "responseHeader" in body and ("status" in body or "cores" in body.lower()):
            # Solr instance reachable
            return CVEResult(
                vulnerable=True,
                url=base + "/solr/admin/cores",
                evidence="Solr admin cores endpoint reachable",
                detail=(
                    "Apache Solr /solr/admin/cores is public. CVE-2021-27905 "
                    "lets the ReplicationHandler fetch arbitrary URLs (SSRF) "
                    "with filesystem write/RCE escalation on unpatched versions."
                ),
            )
        return None
