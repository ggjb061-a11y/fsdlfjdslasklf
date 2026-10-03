#!/usr/bin/env python3
"""
AutoVulnScan performance benchmark suite.

Measures:
  * Module import time
  * Check-class instantiation time
  * Hot-path function timings:
      - categorize_url
      - LinkFinder regex extraction
      - mmh3 hashing
      - CRLF URL building
      - CVEDetector probe setup

Run:
    python3 -m tests.benchmark.bench
    python3 -m tests.benchmark.bench --json results.json
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _timed(fn, iterations: int = 1000):
    """Return (median_ms, p99_ms, mean_ms) over `iterations` runs."""
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000.0)
    times.sort()
    p99 = times[int(0.99 * iterations) - 1] if iterations >= 100 else max(times)
    return statistics.median(times), p99, statistics.mean(times)


def bench_imports():
    """Measure cold-import time for the main scanner package."""
    t0 = time.perf_counter()
    import importlib
    for mod in ("scanner.models", "scanner.utils", "scanner.checks",
                "scanner.checks.cves", "scanner.recon_sources",
                "scanner.crawler", "scanner.recon", "scanner.vulnscan",
                "scanner.reporter"):
        if mod in sys.modules:
            importlib.reload(sys.modules[mod])
        else:
            importlib.import_module(mod)
    return (time.perf_counter() - t0) * 1000.0


def bench_categorize_url():
    from scanner.utils import categorize_url
    urls = [
        "https://example.com/login",
        "https://example.com/app.js?v=1",
        "https://example.com/.env",
        "https://example.com/api/v1/users",
        "https://example.com/style.css",
    ]
    def _run():
        for u in urls:
            categorize_url(u)
    return _timed(_run, iterations=10000)


def bench_mmh3():
    from scanner.recon import ReconModule
    data = b"test favicon bytes" * 100
    def _run():
        ReconModule._mmh3_hash(data)
    return _timed(_run, iterations=1000)


def bench_crawler_extract():
    from scanner.crawler import CrawlerModule
    import tempfile
    from scanner.utils import create_dirs

    tmp = tempfile.mkdtemp()
    dirs = create_dirs(tmp, "example.com")
    c = CrawlerModule(target="example.com", dirs=dirs,
                      live_hosts=["https://example.com"], threads=1)
    html = ('<html>' + '<a href="/path/{i}">x</a>' * 50
            + '<script>fetch("/api/v{i}");var a="/other/{i}";</script>' * 10
            + '</html>')
    def _run():
        c._extract_urls_from_body(html, "https://example.com/")
    return _timed(_run, iterations=200)


def bench_check_instantiation():
    from scanner.checks import ALL_CHECKS, DirBruteCheck
    import tempfile
    from scanner.utils import create_dirs
    tmp = tempfile.mkdtemp()
    dirs = create_dirs(tmp, "example.com")

    def _run():
        for cls in ALL_CHECKS:
            kwargs = {}
            if cls is DirBruteCheck:
                kwargs["wordlist"] = None
            cls(target="example.com", dirs=dirs, live_hosts=[], threads=1, **kwargs)
    return _timed(_run, iterations=100)


def bench_cve_registry():
    from scanner.checks.cves import ALL_CVE_DETECTORS
    def _run():
        for cls in ALL_CVE_DETECTORS:
            cls(lambda cmd, **kw: (0, "", ""))
    return _timed(_run, iterations=100)


BENCHMARKS = [
    ("imports (cold)", lambda: (bench_imports(), 0.0, 0.0)),
    ("categorize_url (per 5 URLs)", bench_categorize_url),
    ("mmh3_hash", bench_mmh3),
    ("crawler extract (large HTML)", bench_crawler_extract),
    ("instantiate 34 checks", bench_check_instantiation),
    ("instantiate 20 CVE detectors", bench_cve_registry),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="Also write results as JSON")
    args = parser.parse_args()

    print(f"{'Benchmark':40s} {'median':>10s} {'p99':>10s} {'mean':>10s}")
    print("-" * 74)
    results = []
    for name, fn in BENCHMARKS:
        median, p99, mean = fn()
        print(f"{name:40s} {median:>8.3f}ms {p99:>8.3f}ms {mean:>8.3f}ms")
        results.append({"name": name, "median_ms": median,
                        "p99_ms": p99, "mean_ms": mean})
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print(f"\nJSON written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
