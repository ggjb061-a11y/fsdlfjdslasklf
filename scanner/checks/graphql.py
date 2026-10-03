"""GraphQL introspection detection."""
import json
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class GraphQLCheck(BaseCheck):
    name = "GraphQL Introspection"
    description = "Detect GraphQL endpoints with introspection enabled"

    GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query",
                     "/graphql/v1", "/api/gql"]
    INTROSPECTION_QUERY = '{"query":"{__schema{types{name,fields{name}}}}"}'

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for path in self.GRAPHQL_PATHS:
                url = f"{base}{path}"
                rc, body, _ = run(
                    ["curl", "-s", "--max-time", "8",
                     "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "-d", self.INTROSPECTION_QUERY, url],
                    timeout=12,
                )
                if rc != 0 or not body:
                    continue
                if '"__schema"' in body and '"types"' in body:
                    try:
                        data = json.loads(body)
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t.get("name", "") for t in types[:20]
                                      if not t.get("name", "").startswith("__")]
                    except Exception:
                        type_names = []
                    self.findings.append(Finding(
                        severity="medium",
                        title="GraphQL Introspection Enabled",
                        host=base,
                        detail=f"Full schema exposed at {url}. Types: {', '.join(type_names[:10])}",
                        source="graphql",
                        url=url,
                        evidence=body[:500],
                    ))
                    break

        return self.findings
