"""
Deep GraphQL probing - triggers only when introspection succeeds.

Checks:
  1. Introspection enabled (full schema dump)
  2. Field-suggestion information disclosure (even with introspection off,
     GraphQL servers often return "Did you mean X?" revealing schema)
  3. Query batching DoS (array of queries in one request)
  4. Alias-based amplification DoS
  5. Unauthenticated sensitive queries (users / me / admin / password)
"""
import json
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class GraphQLDeepCheck(BaseCheck):
    name = "GraphQL Deep"
    description = (
        "Deep GraphQL probing: introspection schema dump, field-suggestion "
        "info disclosure, query batching DoS, alias amplification, "
        "unauthenticated sensitive query access."
    )

    PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query",
             "/graphql/v1", "/api/gql"]

    SENSITIVE_FIELDS = [
        "users", "user", "me", "admin", "adminUsers", "allUsers",
        "secrets", "apiKeys", "tokens", "passwords", "credentials",
        "accounts", "customers", "profiles", "orders", "payments",
    ]

    INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name},mutationType{name},types{name,kind,fields{name,args{name,type{name}}}}}}"}'

    def _post_json(self, url: str, payload: str, timeout: int = 8) -> tuple[int, str]:
        rc, body, _ = run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-X", "POST", "-H", "Content-Type: application/json",
             "-w", "\n__STATUS__:%{http_code}",
             "-d", payload, url],
            timeout=timeout + 4,
        )
        import re
        if rc != 0 or not body:
            return 0, ""
        m = re.search(r"__STATUS__:(\d+)\s*$", body)
        status = int(m.group(1)) if m else 0
        return status, body[:m.start()] if m else body

    def _is_graphql(self, url: str) -> bool:
        status, body = self._post_json(url, '{"query":"{"}')
        if not body:
            return False
        return ("errors" in body and ("GraphQL" in body or "Syntax Error" in body
                                       or "parse" in body.lower()))

    def _check_endpoint(self, url: str) -> None:
        # Stage 1: Introspection
        status, body = self._post_json(url, self.INTROSPECTION_QUERY)
        if body and '"__schema"' in body:
            try:
                data = json.loads(body)
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                type_names = [t.get("name", "") for t in types[:50]
                              if not t.get("name", "").startswith("__")]
            except Exception:
                type_names = []
            self.findings.append(Finding(
                severity="medium",
                title="GraphQL Introspection Enabled",
                host=url,
                detail=(
                    f"Full schema exposed via introspection ({len(type_names)} types). "
                    f"Sample: {', '.join(type_names[:15])}"
                ),
                source="graphql_deep",
                url=url,
                tags=["graphql", "introspection"],
                evidence=body[:500],
            ))

            # Stage 5: Sensitive query probing
            for field in self.SENSITIVE_FIELDS:
                if field in body:
                    probe = json.dumps({"query": f"{{{field}{{id}}}}"})
                    s2, b2 = self._post_json(url, probe)
                    if b2 and '"data"' in b2 and '"errors"' not in b2:
                        # Do NOT dump response bytes: by construction this is a
                        # query for `secrets`/`apiKeys`/`passwords`/etc. and the
                        # first 300 bytes are the leaked data themselves.
                        self.findings.append(Finding(
                            severity="high",
                            title=f"GraphQL unauthenticated sensitive query: {field}",
                            host=url,
                            detail=(
                                f"Query '{{{field}{{id}}}}' returned data without "
                                f"authentication. Sensitive data likely exposed."
                            ),
                            source="graphql_deep",
                            url=url,
                            tags=["graphql", "unauthenticated", "sensitive",
                                  f"field:{field}"],
                            evidence=f"field={field} status={s2} response_bytes={len(b2)}",
                        ))

        # Stage 2: Field-suggestion disclosure (works even without introspection)
        s, b = self._post_json(url, '{"query":"{xxxyyy}"}')
        if b and ("Did you mean" in b or "didYouMean" in b.lower()):
            self.findings.append(Finding(
                severity="medium",
                title="GraphQL Field Suggestion Disclosure",
                host=url,
                detail=(
                    "GraphQL server returns 'Did you mean' suggestions for unknown "
                    "fields - leaks schema even with introspection disabled."
                ),
                source="graphql_deep",
                url=url,
                tags=["graphql", "info-disclosure", "field-suggestion"],
                evidence=b[:300],
            ))

        # Stage 3: Query batching
        batch = json.dumps([{"query": "{ __typename }"}] * 10)
        s, b = self._post_json(url, batch)
        if b and b.count('"__typename"') >= 5:
            self.findings.append(Finding(
                severity="medium",
                title="GraphQL Query Batching Enabled (DoS risk)",
                host=url,
                detail=(
                    "Server accepts array of queries in one request. 10 queries in "
                    "a single request processed - amplifies DoS surface."
                ),
                source="graphql_deep",
                url=url,
                tags=["graphql", "batching", "dos-risk"],
            ))

        # Stage 4: Alias amplification
        aliases = ",".join([f'a{i}:__typename' for i in range(20)])
        s, b = self._post_json(url, json.dumps({"query": f"{{{aliases}}}"}))
        if b and b.count('"__typename"') >= 10 or b.count('"a') >= 10:
            self.findings.append(Finding(
                severity="low",
                title="GraphQL Alias Amplification Possible",
                host=url,
                detail=(
                    "Server executes 20 aliased queries in one request. Combined "
                    "with expensive resolvers this enables DoS."
                ),
                source="graphql_deep",
                url=url,
                tags=["graphql", "alias", "dos-risk"],
            ))

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for path in self.PATHS:
                url = base + path
                if self._is_graphql(url):
                    self.log.info(f"  GraphQL endpoint: {url}")
                    try:
                        self._check_endpoint(url)
                    except Exception as exc:
                        self.log.debug(f"  graphql_deep {url}: {exc}")
                    break
        return self.findings
