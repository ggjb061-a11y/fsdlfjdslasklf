"""PoC-02: curl reads a local file when a POST body starts with "@".

Root cause: BaseCheck._curl_args() passes the body as `curl -d <data>`.
curl treats a leading "@" in -d as "read the body from this local file".
So `_post(url, data="@/some/path")` uploads that local file's content.

Impact: latent. The scanner does not currently pass target-controlled text
into BaseCheck._post (form_fuzzer URL-encodes its values, which removes the
leading "@"). Any future caller that passes raw target data would expose
local files to the target.

Expected (vulnerable): the stub server receives the file's contents.
Control: plain data is sent unchanged.
"""
import tempfile
from pathlib import Path

from _common import Recorder, report

from scanner.checks.base import BaseCheck

MARKER = "LOCAL-FILE-MARKER-7f3a"


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="poc02_"))
    secret = tmp / "local_secret.txt"
    secret.write_text(MARKER)

    stub = Recorder()
    check = BaseCheck("example.com", {"vuln": str(tmp)}, [])
    try:
        # Control: ordinary data reaches the server verbatim.
        check._post(stub.url, data="plain-body-123")
        control_ok = stub.last.get("body") == b"plain-body-123"

        # Vulnerable input: a leading "@" makes curl read a local file.
        check._post(stub.url, data=f"@{secret}")
        leaked = stub.last.get("body", b"").decode(errors="replace")
    finally:
        stub.close()

    confirmed = control_ok and MARKER in leaked
    detail = (f"control_ok={control_ok}; server received body={leaked[:60]!r}")
    return report("PoC-02", "curl -d '@file' reads local files into POST bodies",
                  confirmed, detail)


if __name__ == "__main__":
    raise SystemExit(main())
