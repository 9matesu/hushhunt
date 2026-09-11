from __future__ import annotations

import json
import pathlib
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ponytail: single-file UI; split PAGE into templates/ only if it passes ~800 lines
PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>HushHunt Command Center</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Consolas,Menlo,monospace;background:#0d1117;color:#c9d1d9;display:flex;min-height:100vh}
#side{width:230px;background:#010409;border-right:1px solid #30363d;padding:16px 0;flex-shrink:0}
#side h1{color:#f0883e;font-size:16px;padding:0 16px 12px;border-bottom:1px solid #21262d;margin-bottom:12px}
#side button{display:block;width:100%;text-align:left;background:none;border:none;color:#8b949e;
  padding:10px 16px;font:inherit;font-size:13px;cursor:pointer;border-left:3px solid transparent}
#side button:hover{color:#c9d1d9;background:#161b22}
#side button.on{color:#58a6ff;border-left-color:#f0883e;background:#161b22}
#main{flex:1;padding:20px;overflow-y:auto;max-width:1200px}
.tab{display:none}.tab.on{display:block}
.card{background:#161b22;padding:14px;border:1px solid #30363d;border-radius:6px;margin-bottom:14px}
h2{color:#58a6ff;margin-bottom:10px;font-size:16px}
.kpis{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.kpi{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 18px;min-width:130px}
.kpi b{display:block;font-size:24px;color:#f0883e}
.kpi small{color:#8b949e}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #21262d}
th{color:#58a6ff}
tr:hover td{background:#1c2128}
a{color:#58a6ff}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;margin-right:4px}
.paid{background:#1a472a;color:#7ee787}.vdp{background:#33272a;color:#f08080}
.sev-high{background:#5a1a1a;color:#ff7b72}.sev-medium{background:#4a3500;color:#ffa657}
.sev-low{background:#1c2f4a;color:#79c0ff}.sev-info{background:#21262d;color:#8b949e}
pre{background:#0d1117;padding:8px;overflow-x:auto;border:1px solid #21262d;border-radius:4px;font-size:12px}
input[type=text]{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:6px 10px;
  border-radius:4px;font:inherit;width:100%;margin-bottom:10px}
.good{border-left:3px solid #3fb950}.bad{border-left:3px solid #6e7681}
.funnel{display:flex;align-items:center;gap:6px;margin:10px 0;flex-wrap:wrap}
.fstep{background:#1c2128;border:1px solid #30363d;border-radius:6px;padding:8px 14px;text-align:center}
.fstep b{color:#f0883e;font-size:18px}.arrow{color:#6e7681;font-size:20px}
.bar-row{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:12px}
.bar-lbl{width:170px;text-align:right;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{height:14px;background:#1f6feb;border-radius:2px;min-width:2px}
.donut{display:flex;gap:14px;flex-wrap:wrap;align-items:center}
.legend{font-size:12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}
.explain{background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:10px;margin:8px 0;font-size:13px}
.explain b{color:#7ee787}
</style>
</head>
<body>
<div id="side">
<h1>HushHunt</h1>
<button class="on" data-t="t-overview">Command Center</button>
<button data-t="t-triage">Good vs Bad Info</button>
<button data-t="t-domains">Domain &amp; Target Map</button>
<button data-t="t-vulns">Vulnerabilities</button>
<button data-t="t-live">Live Traffic &amp; Logs</button>
</div>
<div id="main">
<div class="tab on" id="t-overview">
  <div class="kpis" id="kpis">Loading...</div>
  <div class="card"><h2>Pipeline Funnel</h2><div class="funnel" id="funnel"></div></div>
  <div class="card"><h2>Status Codes</h2><div class="donut" id="donut"></div></div>
  <div class="card"><h2>Signals by Check</h2><div id="bars"></div></div>
</div>
<div class="tab" id="t-triage">
  <div class="card"><h2>What to care about (Good Info = possible money)</h2>
    <div class="explain"><b>JWT leaks</b> — auth tokens in public JS bundles. If the token is long-lived
    and accepted by an API, an attacker replays it. Check <span style="color:#8b949e">exp / alg / which host accepts it</span>.</div>
    <div class="explain"><b>CORS with credentials</b> — server reflects ANY Origin with
    <span style="color:#8b949e">Access-Control-Allow-Credentials: true</span>. Only a real bug when the
    endpoint serves private data AND the browser sends cookies there.</div>
    <div class="explain"><b>SSTI / SQLi / XSS</b> — your input evaluated or reflected by the backend.
    Needs a verified proof (math evaluated to 49, error strings, marker reflected).</div>
    <div class="explain"><b>Nuclei hits</b> — matched CVE/misconfig templates (low/medium/high/critical only).</div>
  </div>
  <div class="card"><h2>What gets dropped (Noise / Bad Info)</h2>
    <div class="explain">Missing CSP / HSTS / X-Frame-Options on marketing pages — informational, $0.
    Public telemetry keys (Google Analytics, LaunchDarkly client SDK, Mixpanel) — meant to be public.
    robots.txt / sitemap.xml / standard 404s — not vulnerabilities.</div>
  </div>
  <div class="card"><h2>Live Actionable Signals</h2><div id="good-list">Loading...</div></div>
</div>
<div class="tab" id="t-domains">
  <div class="card"><h2>Target Scopes &amp; Domain Explorer</h2>
    <input type="text" id="domq" placeholder="filter: domain keyword, e.g. api, sandbox, kucoin ...">
    <div id="dom-list">Loading...</div>
  </div>
</div>
<div class="tab" id="t-vulns">
  <div class="card"><h2>Vulnerability &amp; Signal Vault</h2><div id="vuln-list">Loading...</div></div>
</div>
<div class="tab" id="t-live">
  <div class="card"><h2>Live Traffic (last 50 requests)</h2><div id="traffic">Loading...</div></div>
  <div class="card"><h2>Runner Log (live tail)</h2><pre id="log">Waiting...</pre></div>
</div>
</div>
<script>
document.querySelectorAll('#side button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#side button').forEach(x=>x.classList.remove('on'));
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
  b.classList.add('on');document.getElementById(b.dataset.t).classList.add('on');});
const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;');
const COL={2:'#3fb950',3:'#58a6ff',4:'#d29922',5:'#f85149'};
fetch('/api/summary').then(r=>r.json()).then(j=>{
  const f=j.findings||{};
  document.getElementById('kpis').innerHTML=
    `<div class="kpi"><b>${j.total_requests}</b><small>requests sent</small></div>`+
    `<div class="kpi"><b>${j.total_signals}</b><small>signals found</small></div>`+
    `<div class="kpi"><b>${f.verified||0}</b><small>verified bugs</small></div>`+
    `<div class="kpi"><b>${f.dropped||0}</b><small>dropped (noise)</small></div>`+
    `<div class="kpi"><b>${esc(j.llm_spend||'$0')}</b><small>AI triage spend</small></div>`;
  document.getElementById('funnel').innerHTML=
    [`Requests<br><b>${j.total_requests}</b>`,`Signals<br><b>${j.total_signals}</b>`,
     `Dropped<br><b>${f.dropped||0}</b>`,`Verified<br><b>${f.verified||0}</b>`,
     `Reported<br><b>${f.reported||0}</b>`].map(s=>`<div class="fstep">${s}</div>`).join('<div class="arrow">→</div>');
  const bc=j.by_check||{};const mx=Math.max(1,...Object.values(bc));
  document.getElementById('bars').innerHTML=Object.entries(bc).sort((a,b)=>b[1]-a[1])
    .map(([k,v])=>`<div class="bar-row"><div class="bar-lbl">${esc(k)}</div>`+
    `<div class="bar" style="width:${Math.round(v/mx*400)}px"></div><div>${v}</div></div>`).join('');
  if(j.log_tail)document.getElementById('log').textContent=j.log_tail.join('\\n');
});
fetch('/api/traffic').then(r=>r.json()).then(t=>{
  const sc=t.status_codes||{};const tot=Object.values(sc).reduce((a,b)=>a+b,0)||1;
  let a0=0,svg='';
  for(const[code,n]of Object.entries(sc).sort()){
    const frac=n/tot,a1=a0+frac*2*Math.PI;
    const x0=50+40*Math.cos(a0),y0=50+40*Math.sin(a0),x1=50+40*Math.cos(a1),y1=50+40*Math.sin(a1);
    const big=frac>0.5?1:0;
    svg+=`<path d="M50,50 L${x0.toFixed(1)},${y0.toFixed(1)} A40,40 0 ${big},1 ${x1.toFixed(1)},${y1.toFixed(1)} Z" fill="${COL[String(code)[0]]||'#888'}"/>`;
    a0=a1;
  }
  const leg=Object.entries(sc).sort().map(([c,n])=>
    `<div><i style="background:${COL[String(c)[0]]||'#888'}"></i>${c}: ${n}</div>`).join('');
  document.getElementById('donut').innerHTML=
    `<svg width="120" height="120" viewBox="0 0 100 100">${svg}</svg><div class="legend">${leg}<div style="margin-top:6px">avg latency: ${t.avg_latency_ms} ms</div></div>`;
});
let DOMS=[];
fetch('/api/programs').then(r=>r.json()).then(p=>{
  DOMS=p;
  const render=q=>{
    const rows=p.filter(d=>!q||d.id.includes(q)||(d.includes||[]).join(' ').includes(q)).slice(0,120);
    document.getElementById('dom-list').innerHTML=
      `<p style="color:#8b949e;margin-bottom:8px">${p.length} programs, showing ${rows.length}</p>`+
      `<table><tr><th>Program</th><th>Bounty</th><th>Reqs</th><th>Signals</th><th>Scope</th></tr>`+
      rows.map(d=>`<tr><td><a href="${esc(d.url||'#')}" target="_blank">${esc(d.id)}</a></td>`+
      `<td>${d.max_bounty?'<span class="badge paid">PAID</span>':'<span class="badge vdp">VDP</span>'}</td>`+
      `<td>${d.request_count}</td><td>${d.signal_count}</td>`+
      `<td>${esc((d.includes||[]).slice(0,3).join(', '))}</td></tr>`).join('')+`</table>`;
  };
  render('');
  document.getElementById('domq').oninput=e=>render(e.target.value.toLowerCase());
});
fetch('/api/signals').then(r=>r.json()).then(s=>{
  const sev=c=>c.includes('high')?'sev-high':c.includes('medium')?'sev-medium':c.includes('low')?'sev-low':'sev-info';
  const row=x=>`<tr><td>#${x.id}</td><td>${esc(x.program_id)}</td>`+
    `<td>${esc(x.check_id)}</td><td><span class="badge ${sev(x.severity_hint||'info')}">${esc(x.severity_hint||'?')}</span></td>`+
    `<td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.asset)}">${esc(x.asset)}</td></tr>`;
  document.getElementById('good-list').innerHTML=
    `<p style="color:#8b949e">${s.actionable.length} actionable</p><table>`+
    s.actionable.slice(0,60).map(row).join('')+`</table>`;
  document.getElementById('vuln-list').innerHTML=
    `<p style="color:#8b949e">${s.actionable.length} actionable / ${s.noise.length} noise</p><table>`+
    s.actionable.slice(0,100).map(row).join('')+`</table>`;
});
fetch('/api/recent').then(r=>r.json()).then(t=>{
  document.getElementById('traffic').innerHTML=`<table>`+
    t.slice(0,50).map(x=>`<tr><td>${x.status||'?'}</td><td>${esc(x.program_id)}</td>`+
    `<td style="max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.url)}">${esc(x.url)}</td></tr>`).join('')+`</table>`;
});
setInterval(()=>{fetch('/api/summary').then(r=>r.json()).then(j=>{
  if(j.log_tail)document.getElementById('log').textContent=j.log_tail.join('\\n');});},8000);
</script>
</body></html>"""


def _ro(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def query_summary(db_path: str) -> dict:
    conn = _ro(db_path)
    try:
        total_requests = conn.execute("SELECT COUNT(*) c FROM request_log").fetchone()["c"]
        total_signals = conn.execute("SELECT COUNT(*) c FROM signals").fetchone()["c"]
        by_check = {r["check_id"]: r["n"] for r in
                    conn.execute("SELECT check_id, COUNT(*) n FROM signals GROUP BY 1")}
        findings = {r["stage"]: r["n"] for r in
                    conn.execute("SELECT stage, COUNT(*) n FROM findings GROUP BY 1")}
        last = conn.execute(
            "SELECT program_id, ts, url FROM request_log ORDER BY id DESC LIMIT 1").fetchone()
        return {"total_requests": total_requests, "total_signals": total_signals,
                "by_check": by_check, "findings": findings,
                "last_request": dict(last) if last else None}
    finally:
        conn.close()


def query_recent(db_path: str, limit: int = 20) -> list[dict]:
    conn = _ro(db_path)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT program_id, ts, url, status FROM request_log ORDER BY id DESC LIMIT ?",
            (limit,))]
    finally:
        conn.close()


# ponytail: full-table GROUP BY scans; add index on request_log(program_id) past ~500k rows
def query_programs(db_path: str, limit: int = 500) -> list[dict]:
    conn = _ro(db_path)
    try:
        req_counts = {r["program_id"]: r["c"] for r in
                      conn.execute("SELECT program_id, COUNT(*) c FROM request_log GROUP BY 1")}
        sig_counts = {r["program_id"]: r["c"] for r in
                      conn.execute("SELECT program_id, COUNT(*) c FROM signals GROUP BY 1")}
        rows = conn.execute(
            "SELECT id, platform, name, url, max_bounty, safe_harbor, scope_json "
            "FROM programs ORDER BY max_bounty DESC, id ASC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                sc = json.loads(d.get("scope_json") or "{}")
            except (ValueError, TypeError):
                sc = {}
            d["includes"] = sc.get("includes", [])
            d["excludes"] = sc.get("excludes", [])
            d["request_count"] = req_counts.get(d["id"], 0)
            d["signal_count"] = sig_counts.get(d["id"], 0)
            out.append(d)
        return out
    finally:
        conn.close()


NOISE_CHECKS = {"passive_headers", "tls_config"}


def query_signals_categorized(db_path: str, limit: int = 150) -> dict[str, list[dict]]:
    conn = _ro(db_path)
    try:
        rows = conn.execute(
            """SELECT s.id, s.program_id, s.asset, s.check_id, s.wstg, s.severity_hint,
                      s.payload_json, s.evidence_dir, s.created_at, f.stage, f.confidence
               FROM signals s
               LEFT JOIN findings f ON f.signal_id = s.id
               ORDER BY s.id DESC LIMIT ?""", (limit,)).fetchall()
        actionable, noise = [], []
        for r in rows:
            item = dict(r)
            try:
                item["payload"] = json.loads(item.get("payload_json") or "{}")
            except (ValueError, TypeError):
                item["payload"] = {}
            asset = item.get("asset") or ""
            if item["check_id"] in NOISE_CHECKS or (
                    item["check_id"] == "exposed_files"
                    and any(k in asset for k in ("robots.txt", "sitemap.xml"))):
                noise.append(item)
            else:
                actionable.append(item)
        return {"actionable": actionable, "noise": noise}
    finally:
        conn.close()


def query_traffic_stats(db_path: str) -> dict:
    conn = _ro(db_path)
    try:
        status_rows = conn.execute(
            "SELECT status, COUNT(*) c FROM request_log GROUP BY 1").fetchall()
        statuses = {int(r["status"]): int(r["c"]) for r in status_rows if r["status"]}
        avg_ms = conn.execute("SELECT AVG(ms) a FROM request_log").fetchone()["a"] or 0
        return {"status_codes": statuses,
                "avg_latency_ms": round(avg_ms, 1),
                "total_logged": sum(statuses.values())}
    finally:
        conn.close()


def run_server(db_path: str, log_path: str | None, port: int = 8765):
    db, log = db_path, log_path

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype: str):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj) -> None:
            self._send(json.dumps(obj).encode("utf-8"), "application/json")

        def do_GET(self):
            if self.path == "/":
                self._send(PAGE.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path == "/api/summary":
                s = query_summary(db)
                try:
                    import pathlib as _pl
                    cost = _pl.Path(db).parent / "llm_cost.json"
                    usage = json.loads(cost.read_text())
                    calls = usage.get("calls", 0)
                    spend = usage.get("cost_usd", 0.0)
                    s["llm_spend"] = f"${spend:.4f} ({calls} calls)"
                except (OSError, ValueError, KeyError):
                    s["llm_spend"] = "$0"
                if log:
                    try:
                        lines = pathlib.Path(log).read_bytes()[-6000:].decode(
                            "utf-8", "replace").splitlines()
                        s["log_tail"] = lines[-25:]
                    except OSError:
                        s["log_tail"] = []
                self._json(s)
            elif self.path == "/api/recent":
                self._json(query_recent(db, 50))
            elif self.path == "/api/programs":
                self._json(query_programs(db))
            elif self.path == "/api/signals":
                self._json(query_signals_categorized(db))
            elif self.path == "/api/traffic":
                self._json(query_traffic_stats(db))
            elif self.path == "/api/log":
                lines: list[str] = []
                if log:
                    try:
                        lines = pathlib.Path(log).read_bytes()[-12000:].decode(
                            "utf-8", "replace").splitlines()[-100:]
                    except OSError:
                        pass
                self._json({"lines": lines})
            else:
                self.send_response(404)
                self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    return srv, srv.server_address[1]
