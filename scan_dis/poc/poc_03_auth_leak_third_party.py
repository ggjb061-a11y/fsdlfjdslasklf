"""PoC-03: target credentials are sent to third-party OSINT services.

Root cause: utils.run() prepends the globally registered auth material
(Authorization, Cookie, -u) to EVERY curl command, not only to requests that
go to the scan target. recon_sources/_helpers.py (crt.sh, hackertarget,
rapiddns, urlscan, ...) and checks such as s3_buckets.py use this path, so the
user's bearer token / session cookie leaves for those third parties.

The "third party" here is a local stub on 127.0.0.1, so no external host is
contacted. The code path is the real one: http_get_text() from the recon
source helpers.

Expected (vulnerable): the stub, playing the third party, receives the
Authorization and Cookie headers meant for the target.
"""
from _common import Recorder, report

from scanner import utils
from scanner.recon_sources._helpers import http_get_text

BEARER = "TARGET-BEARER-TOKEN-9c1e"
COOKIE = "session=TARGET-SESSION-COOKIE-4b2d"


def main() -> int:
    third_party = Recorder(body=b"subdomain.example.com\n")
    utils.set_auth(bearer=BEARER, cookie=COOKIE)
    try:
        # What the hackertarget / crt.sh / rapiddns sources do.
        body = http_get_text(third_party.url + "hostsearch/?q=example.com")
    finally:
        utils.set_auth()  # reset global auth state
        third_party.close()

    seen = third_party.last.get("headers", {})
    auth_seen = seen.get("authorization", "")
    cookie_seen = seen.get("cookie", "")
    confirmed = (BEARER in auth_seen) and (COOKIE in cookie_seen)
    detail = (f"third party received Authorization={auth_seen!r}, "
              f"Cookie={cookie_seen!r}; body_ok={bool(body)}")
    return report("PoC-03", "target Bearer token and Cookie leak to third-party recon APIs",
                  confirmed, detail)


if __name__ == "__main__":
    raise SystemExit(main())
