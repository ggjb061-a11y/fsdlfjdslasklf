"""Shared helpers for the scan_dis PoCs.

Every PoC talks only to 127.0.0.1 (a local stub server started by the PoC
itself). Nothing here touches a real target or a third-party service.
"""
import http.server
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class Recorder:
    """Local HTTP stub that records the last request it received."""

    def __init__(self, body: bytes = b"ok"):
        self.body = body
        self.last = {}
        recorder = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                payload = self.rfile.read(length) if length else b""
                recorder.last = {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": payload,
                }
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(recorder.body)))
                self.end_headers()
                self.wfile.write(recorder.body)

            do_GET = _handle
            do_POST = _handle

            def log_message(self, *args):  # keep PoC output clean
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def report(poc_id: str, title: str, confirmed: bool, detail: str) -> int:
    verdict = "CONFIRMED" if confirmed else "NOT REPRODUCED"
    print(f"[{verdict}] {poc_id}: {title}")
    print(f"    {detail}")
    return 0 if confirmed else 1
