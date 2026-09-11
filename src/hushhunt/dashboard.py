from __future__ import annotations

import json
import pathlib
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>HushHunt Live Dashboard</title>
<style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:20px;line-height:1.4}
h1,h2{color:#58a6ff;margin-bottom:8px}
.card{background:#161b22;padding:12px;border:1px solid #30363d;border-radius:6px;margin-bottom:12px}
.stat{display:inline-block;margin-right:24px}
.stat span{font-size:1.4em;font-weight:bold;color:#f0883e}
pre{background:#0d1117;padding:8px;overflow-x:auto;border:1px solid #21262d;border-radius:4px}
</style>
</head>
<body>
<h1>HushHunt Live Dashboard</h1>
<div class="card" id="totals">Loading...</div>
<div class="card">
  <h2>Recent Log (Live Tail)</h2>
  <pre id="log">Waiting for log...</pre>
</div>
<script>
fetch('/api/summary').then(r=>r.json()).then(j=>{
  let h = `<div class="stat">Requests: <span>${j.total_requests}</span></div>`;
  h += `<div class="stat">Signals: <span>${j.total_signals}</span></div>`;
  h += `<div class="stat">Verified: <span>${(j.findings&&j.findings.verified)||0}</span></div>`;
  h += `<p><b>Last request:</b> ${j.last_request ? j.last_request.url + ' (' + j.last_request.ts + ')' : 'none'}</p>`;
  h += `<p><b>Top Signals:</b> ` + Object.entries(j.by_check||{}).map(([k,v])=>`${k}: ${v}`).join(' | ') + `</p>`;
  document.getElementById('totals').innerHTML = h;
  if(j.log_tail && j.log_tail.length){
    document.getElementById('log').textContent = j.log_tail.join('\\n');
  }
}).catch(e=>{document.getElementById('totals').textContent = 'Error loading stats: ' + e;});
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

        def do_GET(self):
            if self.path == "/":
                self._send(PAGE.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path == "/api/summary":
                s = query_summary(db)
                if log:
                    try:
                        p = pathlib.Path(log)
                        lines = p.read_bytes()[-6000:].decode("utf-8", "replace").splitlines()
                        s["log_tail"] = lines[-25:]
                    except OSError:
                        s["log_tail"] = []
                self._send(json.dumps(s).encode("utf-8"), "application/json")
            elif self.path == "/api/recent":
                self._send(json.dumps(query_recent(db)).encode("utf-8"), "application/json")
            else:
                self.send_response(404)
                self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    return srv, srv.server_address[1]
