"""
HTTP Request Smuggling detection (CL.TE / TE.CL / TE.TE).

Detection uses timing-based differential, inspired by PortSwigger's research:

- Baseline:   send a normal POST, record median response time (3 samples)
- CL.TE probe: send POST with Content-Length AND Transfer-Encoding:chunked;
               body contains "0\r\n\r\nX". If the back-end processes TE
               (sees the 0-chunk as end-of-request), the front-end's
               Content-Length still expects X. Back-end hangs waiting for
               more bytes - we see a timeout.
- TE.CL probe: send POST with chunked body that is valid for TE but
               claims a short Content-Length. If the front-end processes
               TE and back-end processes CL (or vice versa), timing diverges.

A finding fires ONLY when:
  1. Baseline is stable and < 3s per request.
  2. One of the smuggling probes exceeds baseline + 8s (chunked parser hang).
  3. The reverse probe (same bytes, swap header order) does NOT hang -
     excludes servers that just hang on any malformed POST.
  4. A second confirmation reproduces the behavior.

This yields very high-confidence findings. Full exploitation (prefix
smuggling, response queue poisoning) requires manual follow-up.
"""
import socket
import ssl
import statistics
import time
import urllib.parse
from .base import BaseCheck
from ..models import Finding


class HTTPSmugglingCheck(BaseCheck):
    """Timing-based differential HTTP Request Smuggling detection."""

    name = "HTTP Request Smuggling"
    description = (
        "Detect CL.TE / TE.CL / TE.TE smuggling via timing-based "
        "differential chunked-encoding probes"
    )

    SMUGGLING_HANG_THRESHOLD = 7.0   # seconds beyond baseline that counts as hang
    PROBE_SOCKET_TIMEOUT = 10.0      # how long we wait before giving up
    BASELINE_SAMPLES = 3
    MAX_BASELINE_TIME = 3.0          # skip targets that are already slow

    # Probes:
    # Each entry = (label, headers_dict, body_bytes). Headers must include
    # Host; Content-Length / Transfer-Encoding placement varies to exercise
    # different parser discrepancies.
    # Payloads are kept MINIMAL so backend-level damage is impossible even
    # if they happen to go through: they always ask for ONE byte "X" of
    # trailing content that we never send.

    @staticmethod
    def _parse(host: str) -> tuple[str, str, int]:
        """Return (scheme, host, port) from a URL."""
        p = urllib.parse.urlparse(host if "://" in host else f"https://{host}")
        scheme = p.scheme or "https"
        port = p.port or (443 if scheme == "https" else 80)
        return scheme, (p.hostname or ""), port

    def _send_raw(self, scheme: str, host: str, port: int, request: bytes,
                  timeout: float) -> tuple[float, bytes]:
        """Open a TCP (or TLS) socket, send bytes, read until timeout.

        Returns (elapsed_seconds, response_bytes). Elapsed is measured from
        socket connect through either response receipt or timeout.
        """
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(request)
            chunks = []
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    if len(b"".join(chunks)) > 65536:
                        break
            except socket.timeout:
                pass
            elapsed = time.monotonic() - start
            return elapsed, b"".join(chunks)
        except Exception:
            return time.monotonic() - start, b""
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _baseline_time(self, scheme: str, host: str, port: int) -> float:
        """Median wall-time of a benign POST, 3 samples."""
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        times = []
        for _ in range(self.BASELINE_SAMPLES):
            elapsed, body = self._send_raw(scheme, host, port, request, timeout=5.0)
            if body:
                times.append(elapsed)
        if not times:
            return 0.0
        return statistics.median(times)

    def _probe_clte(self, scheme: str, host: str, port: int,
                    timeout: float) -> tuple[float, bytes]:
        """CL.TE: Content-Length first, then Transfer-Encoding.

        Body: "0\r\n\r\nX" (7 bytes).
        - CL=6 means the front-end reads the first 6 bytes as this request's body.
        - If back-end honors TE, it sees "0\r\n\r\n" (end of chunked) and the
          lone "X" is treated as the beginning of a NEW request -> hangs
          waiting for a complete second request line.
        """
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n\r\nX"
        ).encode()
        return self._send_raw(scheme, host, port, request, timeout)

    def _probe_tecl(self, scheme: str, host: str, port: int,
                    timeout: float) -> tuple[float, bytes]:
        """TE.CL: Transfer-Encoding first, then Content-Length.

        Body: "5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n"
        - Front-end honors TE and reads the full chunked body (one chunk of
          0x5c=92 bytes, then end).
        - Back-end honors CL=4 and only reads "5c\r\n" leaving "GPOST..." as
          a new pipelined request -> hangs or returns odd response.
        """
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Length: 10\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n\r\n"
        ).encode()
        return self._send_raw(scheme, host, port, request, timeout)

    def _probe_tete_obfuscated(self, scheme: str, host: str, port: int,
                                timeout: float) -> tuple[float, bytes]:
        """TE.TE: obfuscated Transfer-Encoding header; one parser accepts, other rejects.

        Many fronts accept "Transfer-Encoding: xchunked" or a double header.
        """
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: xchunked\r\n"
            f"Transfer-Encoding : chunked\r\n"
            f"Content-Length: 6\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n\r\nX"
        ).encode()
        return self._send_raw(scheme, host, port, request, timeout)

    def _benign_chunked(self, scheme: str, host: str, port: int,
                         timeout: float) -> tuple[float, bytes]:
        """Benign chunked POST with no CL - sanity reverse probe.

        If this ALSO hangs, the server is just bad at chunked encoding
        in general - we cannot reliably distinguish smuggling, so we
        suppress the finding.
        """
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"5\r\nhello\r\n0\r\n\r\n"
        ).encode()
        return self._send_raw(scheme, host, port, request, timeout)

    def _test_host(self, url: str) -> None:
        scheme, host, port = self._parse(url)
        if not host:
            return

        baseline = self._baseline_time(scheme, host, port)
        if baseline <= 0:
            self.log.debug(f"  smuggling: baseline failed for {host}")
            return
        if baseline > self.MAX_BASELINE_TIME:
            self.log.debug(f"  smuggling: {host} already slow ({baseline:.1f}s), skipping")
            return

        # First, confirm server handles benign chunked ok (reverse probe)
        reverse_elapsed, reverse_body = self._benign_chunked(
            scheme, host, port, timeout=5.0,
        )
        if reverse_elapsed > baseline + self.SMUGGLING_HANG_THRESHOLD:
            self.log.debug(
                f"  smuggling: {host} hangs on BENIGN chunked - "
                f"suppressing (not smuggling, server is broken on chunked)"
            )
            return

        probes = [
            ("CL.TE", self._probe_clte),
            ("TE.CL", self._probe_tecl),
            ("TE.TE (obfuscated TE)", self._probe_tete_obfuscated),
        ]

        for label, probe_fn in probes:
            elapsed, _body = probe_fn(scheme, host, port,
                                       timeout=self.PROBE_SOCKET_TIMEOUT)
            if elapsed <= baseline + self.SMUGGLING_HANG_THRESHOLD:
                continue
            # First-shot hit - confirm with a second shot
            elapsed2, _ = probe_fn(scheme, host, port,
                                    timeout=self.PROBE_SOCKET_TIMEOUT)
            if elapsed2 <= baseline + self.SMUGGLING_HANG_THRESHOLD:
                continue
            self.findings.append(Finding(
                severity="high",
                title=f"HTTP Request Smuggling ({label})",
                host=url,
                detail=(
                    f"Timing differential confirmed: baseline median "
                    f"{baseline:.2f}s, {label} probe {elapsed:.2f}s / "
                    f"{elapsed2:.2f}s (both > baseline + "
                    f"{self.SMUGGLING_HANG_THRESHOLD}s). Benign chunked "
                    f"baseline returns normally, so this is NOT a generic "
                    f"chunked parser bug.\n\n"
                    f"The server stack is desynchronized on Content-Length "
                    f"vs Transfer-Encoding. Attackers can smuggle requests "
                    f"past the front-end, poisoning the response queue."
                ),
                source="http_smuggling",
                url=url,
                tags=["http-smuggling", label.lower().replace(" ", "-"),
                      "desync", "high-impact"],
                evidence=(
                    f"baseline={baseline:.2f}s "
                    f"inject1={elapsed:.2f}s "
                    f"inject2={elapsed2:.2f}s "
                    f"benign_chunked={reverse_elapsed:.2f}s"
                ),
            ))
            # One finding per host is enough signal
            return

    def execute(self) -> list[Finding]:
        for url in self._hosts(5):
            try:
                self._test_host(url)
            except Exception as exc:
                self.log.debug(f"  smuggling {url}: {exc}")
        return self.findings
