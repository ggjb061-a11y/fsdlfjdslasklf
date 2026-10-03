"""
Report orchestrator: delegates to HTML, JSON, and Markdown generators.
Produces a clean, professional, dark-themed report with collapsible sections.
"""
import logging
from pathlib import Path
from jinja2 import Environment, BaseLoader

logger = logging.getLogger("autoscan.reporter")

REPORT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AutoVulnScan – {{ target }}</title>
<style>
:root{
  --bg:#0d1117;--s1:#161b22;--s2:#1c2129;--bd:#30363d;
  --tx:#e6edf3;--tx2:#8b949e;--ac:#58a6ff;
  --crit:#f85149;--high:#e3a008;--med:#58a6ff;--low:#3fb950;--info:#8b949e;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.6}
a{color:var(--ac);text-decoration:none}
.hdr{background:var(--s1);border-bottom:1px solid var(--bd);padding:20px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.hdr h1{font-size:22px;font-weight:700;letter-spacing:-.4px}
.hdr .meta{color:var(--tx2);font-size:12px}
.wrap{max-width:1260px;margin:0 auto;padding:24px 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:24px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;text-align:center}
.card .n{font-size:32px;font-weight:700;margin-bottom:2px}
.card .l{color:var(--tx2);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.c-cr .n{color:var(--crit)}.c-hi .n{color:var(--high)}.c-me .n{color:var(--med)}.c-lo .n{color:var(--low)}.c-in .n{color:var(--info)}
section{background:var(--s1);border:1px solid var(--bd);border-radius:8px;margin-bottom:16px;overflow:hidden}
section>h2{padding:12px 18px;font-size:14px;font-weight:600;border-bottom:1px solid var(--bd);cursor:pointer;display:flex;justify-content:space-between;align-items:center;user-select:none;transition:background .15s}
section>h2:hover{background:var(--s2)}
section>h2::after{content:"▲";font-size:9px;color:var(--tx2);transition:transform .2s}
section.closed>h2::after{transform:rotate(180deg)}
section.closed>.bd{display:none}
.bd{padding:12px 18px 16px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th{text-align:left;padding:6px 10px;font-size:11px;color:var(--tx2);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bd);white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
.sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;text-transform:uppercase}
.s-critical{background:rgba(248,81,73,.15);color:var(--crit)}
.s-high{background:rgba(227,160,8,.15);color:var(--high)}
.s-medium{background:rgba(88,166,255,.15);color:var(--med)}
.s-low{background:rgba(63,185,80,.15);color:var(--low)}
.s-info{background:rgba(139,148,158,.15);color:var(--info)}
.tag{display:inline-block;padding:1px 5px;border-radius:3px;font-size:10px;background:#21262d;color:var(--tx2);margin:1px}
.chip{display:inline-block;padding:2px 7px;border-radius:4px;font-size:12px;background:#21262d;margin:2px 1px;white-space:nowrap}
pre{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:10px;overflow-x:auto;font-size:12px;margin-top:8px;max-height:400px}
code{font-family:"Fira Code","Cascadia Code",monospace;font-size:12px}
.empty{color:var(--tx2);font-style:italic;padding:10px 0;font-size:13px}
.cnt{color:var(--tx2);font-weight:400;font-size:12px;margin-left:6px}
.flex{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.hl{color:var(--high)}
.ok{color:var(--low)}
ul.ls{margin:6px 0 0 18px;list-style:disc}
ul.ls li{color:var(--tx2);font-size:13px;margin-bottom:2px}
.method-row td:first-child{font-weight:600;white-space:nowrap}
.danger{color:var(--crit);font-weight:700}

@media(max-width:700px){
  .hdr{padding:14px 16px}
  .wrap{padding:16px 8px}
  .grid{grid-template-columns:repeat(3,1fr)}
  table{font-size:12px}
}
</style>
</head>
<body>

<div class="hdr">
  <div>
    <h1>AutoVulnScan Report</h1>
    <div class="meta">Target: <strong>{{ target }}</strong> &nbsp;|&nbsp; {{ scan_date }} &nbsp;|&nbsp; Authorized testing only</div>
  </div>
</div>

<div class="wrap">

<!-- ─── SUMMARY CARDS ────────────────────────────────────────────────── -->
<div class="grid">
  <div class="card c-cr"><div class="n">{{ counts.critical }}</div><div class="l">Critical</div></div>
  <div class="card c-hi"><div class="n">{{ counts.high }}</div><div class="l">High</div></div>
  <div class="card c-me"><div class="n">{{ counts.medium }}</div><div class="l">Medium</div></div>
  <div class="card c-lo"><div class="n">{{ counts.low }}</div><div class="l">Low</div></div>
  <div class="card c-in"><div class="n">{{ counts.info }}</div><div class="l">Info</div></div>
  <div class="card"><div class="n">{{ subdomains|length }}</div><div class="l">Subdomains</div></div>
  <div class="card"><div class="n">{{ live_hosts|length }}</div><div class="l">Live Hosts</div></div>
  <div class="card"><div class="n">{{ urls|length }}</div><div class="l">URLs</div></div>
  <div class="card"><div class="n">{{ js_secrets|length }}</div><div class="l">JS Secrets</div></div>
  <div class="card"><div class="n">{{ emails|length }}</div><div class="l">Emails</div></div>
</div>

<!-- ─── ALL FINDINGS ─────────────────────────────────────────────────── -->
<section id="s-findings">
  <h2 onclick="T('s-findings')">All Findings<span class="cnt">({{ findings|length }})</span></h2>
  <div class="bd">
  {% if findings %}
  <table>
    <thead><tr><th>Sev</th><th>Title</th><th>Host</th><th>Source</th><th>Detail</th></tr></thead>
    <tbody>
    {% for f in findings %}
    <tr>
      <td><span class="sev s-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.title }}</td>
      <td style="max-width:200px">{{ f.host }}</td>
      <td><span class="tag">{{ f.source }}</span></td>
      <td style="max-width:350px">{{ f.detail[:200] }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No findings.</p>{% endif %}
  </div>
</section>

<!-- ─── JS SECRETS ───────────────────────────────────────────────────── -->
<section id="s-js" {% if not js_secrets %}class="closed"{% endif %}>
  <h2 onclick="T('s-js')">JS Secrets<span class="cnt">({{ js_secrets|length }})</span></h2>
  <div class="bd">
  {% if js_secrets %}
  <table>
    <thead><tr><th>Sev</th><th>Pattern</th><th>File</th><th>Line</th><th>Match</th></tr></thead>
    <tbody>
    {% for s in js_secrets %}
    <tr>
      <td><span class="sev s-{{ s.severity }}">{{ s.severity }}</span></td>
      <td>{{ s.pattern_name }}</td>
      <td style="max-width:250px;word-break:break-all">{{ s.file_url }}</td>
      <td>{{ s.line }}</td>
      <td><code>{{ s.match[:80] }}</code></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No secrets found in JS files.</p>{% endif %}
  </div>
</section>

<!-- ─── HTTP METHODS ─────────────────────────────────────────────────── -->
<section id="s-methods" class="closed">
  <h2 onclick="T('s-methods')">HTTP Methods<span class="cnt">({{ methods|length }} hosts)</span></h2>
  <div class="bd">
  {% if methods %}
  <table>
    <thead><tr><th>Host</th><th>Allowed Methods</th></tr></thead>
    <tbody>
    {% for host, meths in methods.items() %}
    <tr class="method-row">
      <td>{{ host }}</td>
      <td>{% for m in meths %}{% if m in ('PUT','DELETE','TRACE','CONNECT') %}<span class="danger">{{ m }}</span>{% else %}{{ m }}{% endif %}{% if not loop.last %}, {% endif %}{% endfor %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No method data.</p>{% endif %}
  </div>
</section>

<!-- ─── SUBDOMAINS ───────────────────────────────────────────────────── -->
<section id="s-subs" class="closed">
  <h2 onclick="T('s-subs')">Subdomains<span class="cnt">({{ subdomains|length }})</span></h2>
  <div class="bd">
  {% if subdomains %}
  <div class="flex">{% for s in subdomains %}<span class="chip">{{ s }}</span>{% endfor %}</div>
  {% else %}<p class="empty">None found.</p>{% endif %}
  </div>
</section>

<!-- ─── LIVE HOSTS ───────────────────────────────────────────────────── -->
<section id="s-hosts" class="closed">
  <h2 onclick="T('s-hosts')">Live Hosts<span class="cnt">({{ host_records|length }})</span></h2>
  <div class="bd">
  {% if host_records %}
  <table>
    <thead><tr><th>#</th><th>Domain</th><th>IP</th><th>Status</th><th>Server</th><th>Title</th><th>Technologies</th></tr></thead>
    <tbody>
    {% for h in host_records %}
    <tr>
      <td>{{ loop.index }}</td>
      <td>{{ h.domain }}</td>
      <td>{{ h.ip or '–' }}</td>
      <td>{{ h.status or '–' }}</td>
      <td>{{ h.server or '–' }}</td>
      <td>{{ h.title[:50] }}</td>
      <td>{% for t in h.technologies %}<span class="tag">{{ t }}</span>{% endfor %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No host data.</p>{% endif %}
  </div>
</section>

<!-- ─── DNS ───────────────────────────────────────────────────────────── -->
<section id="s-dns" class="closed">
  <h2 onclick="T('s-dns')">DNS Records</h2>
  <div class="bd">
  {% if dns %}
  <table>
    <thead><tr><th>Type</th><th>Values</th></tr></thead>
    <tbody>
    {% for rtype, vals in dns.items() %}
    <tr><td><code>{{ rtype }}</code></td><td>{{ vals|join(', ') }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No DNS data.</p>{% endif %}
  </div>
</section>

<!-- ─── URLS ──────────────────────────────────────────────────────────── -->
<section id="s-urls" class="closed">
  <h2 onclick="T('s-urls')">Discovered URLs<span class="cnt">({{ urls|length }})</span></h2>
  <div class="bd">
  {% if urls %}
  <p style="margin-bottom:8px;color:var(--tx2)">
    Login: {{ urls|selectattr('is_login')|list|length }} |
    JS: {{ urls|selectattr('is_js')|list|length }} |
    Sensitive: {{ urls|selectattr('is_sensitive_file')|list|length }} |
    API: {{ urls|selectattr('is_api')|list|length }}
  </p>

  {% set login_urls = urls|selectattr('is_login')|list %}
  {% if login_urls %}
  <h3 style="font-size:13px;margin-top:12px;color:var(--high)">Login / Auth Pages</h3>
  <ul class="ls">{% for u in login_urls[:30] %}<li><a href="{{ u.url }}" target="_blank">{{ u.url }}</a> {% if u.status %}<span class="tag">{{ u.status }}</span>{% endif %}</li>{% endfor %}</ul>
  {% endif %}

  {% set sens = urls|selectattr('is_sensitive_file')|list %}
  {% if sens %}
  <h3 style="font-size:13px;margin-top:12px;color:var(--crit)">Sensitive Files</h3>
  <ul class="ls">{% for u in sens[:30] %}<li><a href="{{ u.url }}" target="_blank">{{ u.url }}</a> {% if u.status %}<span class="tag">{{ u.status }}</span>{% endif %}</li>{% endfor %}</ul>
  {% endif %}

  {% set api = urls|selectattr('is_api')|list %}
  {% if api %}
  <h3 style="font-size:13px;margin-top:12px;color:var(--ac)">API Endpoints</h3>
  <ul class="ls">{% for u in api[:30] %}<li><a href="{{ u.url }}" target="_blank">{{ u.url }}</a> {% if u.status %}<span class="tag">{{ u.status }}</span>{% endif %}</li>{% endfor %}</ul>
  {% endif %}
  {% else %}<p class="empty">No URLs collected.</p>{% endif %}
  </div>
</section>

<!-- ─── JS ENDPOINTS ─────────────────────────────────────────────────── -->
<section id="s-jep" class="closed">
  <h2 onclick="T('s-jep')">JS Endpoints<span class="cnt">({{ js_endpoints|length }})</span></h2>
  <div class="bd">
  {% if js_endpoints %}
  <div class="flex">{% for e in js_endpoints %}<span class="chip">{{ e }}</span>{% endfor %}</div>
  {% else %}<p class="empty">No endpoints extracted from JS.</p>{% endif %}
  </div>
</section>

<!-- ─── DISCOVERED PARAMETERS ──────────────────────────────────────────── -->
<section id="s-params" class="closed">
  <h2 onclick="T('s-params')">Discovered Parameters<span class="cnt">({{ found_params|length }} endpoints)</span></h2>
  <div class="bd">
  {% if found_params %}
  <table>
    <thead><tr><th>Endpoint</th><th>Parameters</th></tr></thead>
    <tbody>
    {% for url, params in found_params.items() %}
    <tr>
      <td style="max-width:400px;word-break:break-all">{{ url }}</td>
      <td>{% for p in params %}<span class="tag">{{ p }}</span>{% endfor %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No parameters discovered.</p>{% endif %}
  </div>
</section>

<!-- ─── EMAILS ────────────────────────────────────────────────────────── -->
<section id="s-emails" class="closed">
  <h2 onclick="T('s-emails')">Emails<span class="cnt">({{ emails|length }})</span></h2>
  <div class="bd">
  {% if emails %}
  <div class="flex">{% for e in emails %}<span class="chip">{{ e }}</span>{% endfor %}</div>
  {% else %}<p class="empty">No emails found.</p>{% endif %}
  </div>
</section>

<!-- ─── CMS ───────────────────────────────────────────────────────────── -->
<section id="s-cms" class="closed">
  <h2 onclick="T('s-cms')">CMS Detection</h2>
  <div class="bd">
  {% if cms_info %}
  <table>
    <thead><tr><th>Host</th><th>CMS / Framework</th></tr></thead>
    <tbody>
    {% for host, cms in cms_info.items() %}
    <tr><td>{{ host }}</td><td><strong>{{ cms }}</strong></td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No CMS detected.</p>{% endif %}
  </div>
</section>

<!-- ─── PORTS ─────────────────────────────────────────────────────────── -->
<section id="s-ports" class="closed">
  <h2 onclick="T('s-ports')">Open Ports</h2>
  <div class="bd">
  {% if ports %}
  <pre>{{ ports|join('\n') }}</pre>
  {% else %}<p class="empty">See recon/ports/ directory for raw output.</p>{% endif %}
  </div>
</section>

<!-- ─── WHOIS ─────────────────────────────────────────────────────────── -->
<section id="s-whois" class="closed">
  <h2 onclick="T('s-whois')">WHOIS</h2>
  <div class="bd">
  {% if whois %}
  <pre>{{ whois }}</pre>
  {% else %}<p class="empty">No WHOIS data.</p>{% endif %}
  </div>
</section>

<!-- ─── WAF ───────────────────────────────────────────────────────────── -->
<section id="s-waf" class="closed">
  <h2 onclick="T('s-waf')">WAF Detection</h2>
  <div class="bd">
  {% if waf %}<pre>{{ waf }}</pre>{% else %}<p class="empty">No WAF data.</p>{% endif %}
  </div>
</section>

<!-- ─── GOOGLE DORKS ──────────────────────────────────────────────────── -->
<section id="s-dorks" class="closed">
  <h2 onclick="T('s-dorks')">Google Dorks<span class="cnt">({{ google_dorks|length }})</span></h2>
  <div class="bd">
  {% if google_dorks %}
  <p style="margin-bottom:8px;color:var(--tx2)">Copy these into Google for manual reconnaissance:</p>
  <table>
    <thead><tr><th>#</th><th>Dork Query</th><th>Link</th></tr></thead>
    <tbody>
    {% for dork in google_dorks %}
    <tr>
      <td>{{ loop.index }}</td>
      <td><code>{{ dork }}</code></td>
      <td><a href="https://www.google.com/search?q={{ dork|urlencode }}" target="_blank">Search</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty">No dork queries generated.</p>{% endif %}
  </div>
</section>

</div>
<script>
function T(id){document.getElementById(id).classList.toggle('closed')}
</script>
</body>
</html>"""


def generate(result) -> str:
    """Render HTML + JSON reports. Returns HTML report path."""
    counts = result.count_by_severity()
    env = Environment(loader=BaseLoader(), autoescape=True)
    tmpl = env.from_string(REPORT_HTML)

    html = tmpl.render(
        target=result.target,
        scan_date=result.scan_date,
        counts=counts,
        findings=[vars(f) for f in result.sorted_findings()],
        js_secrets=[vars(s) for s in result.js_secrets],
        js_endpoints=getattr(result, "js_endpoints", []),
        methods=result.allowed_methods,
        subdomains=result.subdomains,
        live_hosts=result.live_hosts,
        host_records=[vars(h) for h in getattr(result, "host_records", [])],
        dns=result.dns_records,
        urls=[vars(u) for u in result.urls],
        ports=getattr(result, "ports_raw", []),
        whois=result.whois,
        waf=result.waf,
        emails=getattr(result, "emails", []),
        cms_info=getattr(result, "cms_info", {}),
        found_params=getattr(result, "found_params", {}),
        google_dorks=getattr(result, "google_dorks", []),
    )

    html_path = f"{result.base_dir}/06_reports/report.html"
    Path(html_path).write_text(html)
    logger.info(f"  HTML report: {html_path}")

    from .output import generate_json, generate_markdown
    generate_json(result)
    generate_markdown(result)

    return html_path
