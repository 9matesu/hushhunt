from __future__ import annotations

import json
import pathlib
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ponytail: single-file UI; split PAGE into templates/ only if it passes ~1200 lines
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HushHunt — Autonomous Bounty Command Center</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg-base: #08090a;
  --bg-side: #0b0c0e;
  --bg-card: rgba(255, 255, 255, 0.025);
  --bg-card-hover: rgba(255, 255, 255, 0.045);
  --border-subtle: rgba(255, 255, 255, 0.06);
  --border-focus: rgba(113, 112, 255, 0.5);
  --text-primary: #f7f8f8;
  --text-secondary: #d0d6e0;
  --text-muted: #8a8f98;
  --accent-indigo: #5e6ad2;
  --accent-violet: #7170ff;
  --accent-glow: rgba(113, 112, 255, 0.15);
  --status-green: #10b981;
  --status-coral: #ff7b72;
  --status-amber: #d29922;
  --status-blue: #58a6ff;
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg-base);
  color: var(--text-secondary);
  font-family: var(--font-sans);
  font-size: 13px;
  line-height: 1.5;
  display: flex;
  height: 100vh;
  overflow: hidden;
  -webkit-font-smoothing: antialiased;
}

/* Sidebar */
#sidebar {
  width: 260px;
  background: var(--bg-side);
  border-right: 1px solid var(--border-subtle);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  user-select: none;
}
.brand {
  padding: 20px 20px 16px;
  border-bottom: 1px solid var(--border-subtle);
}
.brand-title {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-primary);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: -0.3px;
}
.brand-badge {
  background: linear-gradient(135deg, var(--accent-indigo), var(--accent-violet));
  color: #fff;
  font-size: 9px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
  text-transform: uppercase;
}
.live-pill {
  margin-top: 8px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.25);
  color: var(--status-green);
  font-size: 11px;
  font-weight: 500;
  padding: 2px 8px;
  border-radius: 12px;
}
.live-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--status-green);
  box-shadow: 0 0 6px var(--status-green);
  animation: pulse 1.8s infinite;
}
@keyframes pulse {
  0% { transform: scale(0.95); opacity: 0.8; }
  50% { transform: scale(1.3); opacity: 1; }
  100% { transform: scale(0.95); opacity: 0.8; }
}

.nav-group {
  padding: 16px 12px;
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.nav-btn {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  padding: 8px 12px;
  font-family: inherit;
  font-size: 13px;
  font-weight: 500;
  border-radius: 6px;
  cursor: pointer;
  text-align: left;
  transition: all 0.15s ease;
}
.nav-btn:hover {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.03);
}
.nav-btn.active {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.05);
  border-color: var(--border-subtle);
  box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}
.nav-btn svg { width: 16px; height: 16px; stroke-width: 2; opacity: 0.8; }
.nav-btn.active svg { stroke: var(--accent-violet); opacity: 1; }

.sidebar-foot {
  padding: 14px 16px;
  border-top: 1px solid var(--border-subtle);
  font-size: 11px;
  color: var(--text-muted);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

/* Main Content Area */
#main {
  flex: 1;
  overflow-y: auto;
  padding: 28px 32px;
  background: radial-gradient(circle at 50% 0%, rgba(113, 112, 255, 0.03), transparent 40%);
}
.tab-pane { display: none; }
.tab-pane.active { display: block; animation: fadeIn 0.15s ease; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

/* Cards & Surfaces */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  backdrop-filter: blur(12px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
  transition: border-color 0.15s;
}
.card:hover { border-color: rgba(255, 255, 255, 0.1); }
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.card-title {
  color: var(--text-primary);
  font-size: 14px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
  letter-spacing: -0.2px;
}
.card-desc {
  font-size: 12px;
  color: var(--text-muted);
}

/* KPI Top Grid */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 14px;
  margin-bottom: 20px;
}
.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 16px 18px;
  position: relative;
  overflow: hidden;
}
.kpi-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--accent-violet), transparent);
  opacity: 0.6;
}
.kpi-val {
  font-size: 26px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.5px;
  font-feature-settings: 'cv01', 'ss03';
}
.kpi-lbl {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  margin-top: 4px;
}
.kpi-meta {
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 2px;
}

/* Funnel Visualizer */
.funnel-container {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 0;
  overflow-x: auto;
}
.funnel-step {
  flex: 1;
  min-width: 140px;
  background: rgba(255, 255, 255, 0.015);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  padding: 12px 14px;
  text-align: center;
}
.funnel-step b {
  display: block;
  font-size: 20px;
  color: var(--text-primary);
  font-weight: 700;
}
.funnel-step span {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
}
.funnel-arrow {
  color: var(--text-muted);
  font-size: 14px;
  opacity: 0.4;
}

/* Bar Chart */
.bar-chart { display: flex; flex-direction: column; gap: 8px; }
.bar-item { display: flex; align-items: center; gap: 12px; font-size: 12px; }
.bar-label {
  width: 160px;
  text-align: right;
  color: var(--text-muted);
  font-family: var(--font-mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.bar-track {
  flex: 1;
  height: 18px;
  background: rgba(255, 255, 255, 0.02);
  border-radius: 4px;
  overflow: hidden;
  position: relative;
}
.bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent-indigo), var(--accent-violet));
  border-radius: 4px;
  transition: width 0.4s ease;
}
.bar-val { width: 45px; font-weight: 600; color: var(--text-primary); }

/* Donut Chart & Legend */
.donut-wrap {
  display: flex;
  align-items: center;
  gap: 28px;
  flex-wrap: wrap;
}
.donut-legend { display: flex; flex-direction: column; gap: 6px; font-size: 12px; }
.legend-row { display: flex; align-items: center; gap: 8px; }
.legend-dot { width: 10px; height: 10px; border-radius: 2px; }

/* Tables */
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  text-align: left;
}
th {
  background: rgba(255, 255, 255, 0.02);
  color: var(--text-muted);
  font-weight: 600;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-subtle);
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.5px;
}
td {
  padding: 10px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  color: var(--text-secondary);
}
tr:hover td { background: rgba(255, 255, 255, 0.015); }
a { color: var(--accent-violet); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  font-family: var(--font-mono);
  letter-spacing: 0.3px;
}
.badge-paid { background: rgba(16, 185, 129, 0.15); color: var(--status-green); border: 1px solid rgba(16, 185, 129, 0.3); }
.badge-vdp { background: rgba(255, 255, 255, 0.05); color: var(--text-muted); }
.badge-high { background: rgba(255, 123, 114, 0.15); color: var(--status-coral); border: 1px solid rgba(255, 123, 114, 0.3); }
.badge-medium { background: rgba(210, 153, 34, 0.15); color: var(--status-amber); border: 1px solid rgba(210, 153, 34, 0.3); }
.badge-low { background: rgba(88, 166, 255, 0.15); color: var(--status-blue); }
.badge-info { background: rgba(255, 255, 255, 0.05); color: var(--text-muted); }

/* Triage Cards (Good vs Bad) */
.triage-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 24px;
}
@media (max-width: 900px) { .triage-grid { grid-template-columns: 1fr; } }
.triage-box {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 18px;
}
.triage-box.good { border-left: 3px solid var(--status-green); }
.triage-box.bad { border-left: 3px solid var(--text-muted); }
.triage-item {
  background: rgba(255, 255, 255, 0.015);
  border: 1px solid rgba(255, 255, 255, 0.04);
  border-radius: 6px;
  padding: 12px 14px;
  margin-top: 10px;
  font-size: 12px;
}
.triage-item b { color: var(--text-primary); font-size: 13px; display: block; margin-bottom: 4px; }
.triage-tag { color: var(--accent-violet); font-family: var(--font-mono); font-size: 11px; }

/* Filter & Search Bar */
.search-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
}
.search-input {
  flex: 1;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  color: var(--text-primary);
  padding: 8px 14px;
  font-family: inherit;
  font-size: 13px;
  outline: none;
  transition: border-color 0.15s;
}
.search-input:focus { border-color: var(--accent-violet); }
.filter-pills { display: flex; gap: 6px; }
.pill-btn {
  background: transparent;
  border: 1px solid var(--border-subtle);
  color: var(--text-muted);
  border-radius: 20px;
  padding: 4px 12px;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}
.pill-btn:hover { color: var(--text-primary); border-color: rgba(255,255,255,0.2); }
.pill-btn.active { background: rgba(113, 112, 255, 0.15); color: var(--accent-violet); border-color: var(--accent-violet); }

/* Live Terminal Log */
.terminal {
  background: #050607;
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  padding: 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  max-height: 480px;
  overflow-y: auto;
  color: #c9d1d9;
  white-space: pre-wrap;
  word-break: break-all;
}
.terminal-controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
  font-size: 12px;
  color: var(--text-muted);
}
.terminal-controls label { display: flex; align-items: center; gap: 6px; cursor: pointer; }
</style>
</head>
<body>

<!-- Left Navigation Sidebar -->
<aside id="sidebar">
  <div class="brand">
    <div class="brand-title">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
      <span>HUSH<span style="color:var(--accent-violet)">HUNT</span></span>
      <span class="brand-badge">PRO MAX</span>
    </div>
    <div class="live-pill" id="live-indicator">
      <span class="live-dot"></span>
      <span id="live-status">LIVE MONITORING</span>
    </div>
  </div>

  <nav class="nav-group">
    <button class="nav-btn active" data-tab="tab-overview">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
      Command Center
    </button>
    <button class="nav-btn" data-tab="tab-triage">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"></path></svg>
      Good vs Bad Info
    </button>
    <button class="nav-btn" data-tab="tab-domains">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"></path></svg>
      Target &amp; Scope Map
    </button>
    <button class="nav-btn" data-tab="tab-vulns">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
      Vulnerability Vault
    </button>
    <button class="nav-btn" data-tab="tab-bugs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"></circle><path d="M8 12l2 2 4-5"></path></svg>
      Verified Bugs &amp; Reports
    </button>
    <button class="nav-btn" data-tab="tab-reasoning">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 2a7 7 0 0 1 7 7c0 2.38-1.19 4.47-3 5.74V17a2 2 0 0 1-2 2h-4a2 2 0 0 1-2-2v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 0 1 7-7z"></path><path d="M9 21h6"></path></svg>
      AI Reasoning Feed
    </button>
    <button class="nav-btn" data-tab="tab-live">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
      Live Traffic &amp; Console
    </button>
  </nav>

  <div class="sidebar-foot">
    <span>Autonomous Bot v1.0</span>
    <span id="last-ping" style="color:var(--text-muted);font-family:var(--font-mono)">...</span>
  </div>
</aside>

<!-- Main Interactive Content Panel -->
<main id="main">

  <!-- TAB 1: Command Center -->
  <section class="tab-pane active" id="tab-overview">
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-val" id="kpi-reqs">--</div>
        <div class="kpi-lbl">Total Requests Sent</div>
        <div class="kpi-meta" id="kpi-last-target">Scanning active targets...</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-val" id="kpi-signals">--</div>
        <div class="kpi-lbl">Security Signals Found</div>
        <div class="kpi-meta" id="kpi-signals-rate">Triaged by AI engine</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-val" style="color:var(--status-green)" id="kpi-verified">--</div>
        <div class="kpi-lbl">Verified Vulnerabilities</div>
        <div class="kpi-meta" id="kpi-reported">0 reported</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-val" style="color:var(--text-muted)" id="kpi-dropped">--</div>
        <div class="kpi-lbl">Noise Dropped</div>
        <div class="kpi-meta">Filtered out (NA-KB)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-val" style="color:var(--accent-violet)" id="kpi-spend">$0.00</div>
        <div class="kpi-lbl">AI Reasoning Spend</div>
        <div class="kpi-meta" id="kpi-calls">Local TokenRouter</div>
      </div>
    </div>

    <!-- Funnel Card -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Bug Bounty Conversion Funnel</div>
          <div class="card-desc">How raw HTTP requests turn into verified, paid bounty findings</div>
        </div>
      </div>
      <div class="funnel-container" id="funnel-view">
        <div class="funnel-step"><b id="fn-reqs">0</b><span>Requests</span></div>
        <div class="funnel-arrow">→</div>
        <div class="funnel-step"><b id="fn-sigs">0</b><span>Signals</span></div>
        <div class="funnel-arrow">→</div>
        <div class="funnel-step"><b id="fn-noise" style="color:var(--text-muted)">0</b><span>Dropped Noise</span></div>
        <div class="funnel-arrow">→</div>
        <div class="funnel-step"><b id="fn-ver" style="color:var(--status-green)">0</b><span>Verified Bugs</span></div>
        <div class="funnel-arrow">→</div>
        <div class="funnel-step"><b id="fn-rep" style="color:var(--accent-violet)">0</b><span>Reports Ready</span></div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
      <!-- Status Codes -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">HTTP Response Codes</div>
          <div class="card-desc" id="donut-latency">Avg Latency: -- ms</div>
        </div>
        <div class="donut-wrap" id="donut-view">
          <div style="color:var(--text-muted)">Loading traffic breakdown...</div>
        </div>
      </div>

      <!-- Signals by Check Type -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">Active Checks Breakdown</div>
          <div class="card-desc">Vulnerability vectors tested</div>
        </div>
        <div class="bar-chart" id="bars-view">
          <div style="color:var(--text-muted)">Loading check types...</div>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 2: Good vs Bad Info -->
  <section class="tab-pane" id="tab-triage">
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">HushHunt Triage Intelligence: What Matters &amp; What Doesn't</div>
          <div class="card-desc">Clear guide for naive users: separate high-value bounties from automated noise</div>
        </div>
      </div>

      <div class="triage-grid">
        <!-- Good Info -->
        <div class="triage-box good">
          <h3 style="color:var(--status-green);font-size:14px;margin-bottom:8px">🔥 Good Info (High-Value Bounties)</h3>
          <p style="color:var(--text-muted);font-size:12px">Signals the autonomous loop pursues for payout:</p>

          <div class="triage-item">
            <b>JWT &amp; API Secret Leaks</b>
            Auth tokens or credentials found inside client bundles (.js). If the token is long-lived and accepted by an API endpoint, it grants unauthorized access.
            <div class="triage-tag">Checks: js_secret, exposed_files</div>
          </div>
          <div class="triage-item">
            <b>CORS with Reflected Origin &amp; Credentials</b>
            Server reflects attacker's <span style="color:#fff">Origin</span> along with <span style="color:#fff">Access-Control-Allow-Credentials: true</span>. If the endpoint serves private profile/account data, an attacker can steal it via cross-domain browser requests.
            <div class="triage-tag">Checks: cors_misconfig</div>
          </div>
          <div class="triage-item">
            <b>Server-Side Template Injection (SSTI) &amp; SQLi</b>
            Backend evaluates user input as dynamic code (e.g. <code>{{7*7}} → 49</code>). Can lead directly to Remote Code Execution (RCE) and top-tier bounties ($1,000–$5,000).
            <div class="triage-tag">Checks: ssti, sqli</div>
          </div>
          <div class="triage-item">
            <b>Nuclei CVE &amp; Zero-Day Hits</b>
            Known CVE signatures matched with precision on staging, admin, or API surfaces. Filtered to drop informative noise.
            <div class="triage-tag">Checks: nuclei_cve, misconfig</div>
          </div>
        </div>

        <!-- Bad Info -->
        <div class="triage-box bad">
          <h3 style="color:var(--text-muted);font-size:14px;margin-bottom:8px">🗑️ Bad Info (Ignored Noise)</h3>
          <p style="color:var(--text-muted);font-size:12px">Automatically dropped by HushHunt to avoid wasting time &amp; budget:</p>

          <div class="triage-item">
            <b>Missing Best-Practice Headers</b>
            Missing <code>Content-Security-Policy</code>, <code>X-Frame-Options</code>, or <code>HSTS</code> on static marketing pages. Bug bounty programs award $0 and mark as Informative.
            <div class="triage-tag">Action: Auto-dropped (NA-KB)</div>
          </div>
          <div class="triage-item">
            <b>Public Telemetry &amp; Analytics Keys</b>
            Client-side keys meant to be public: Google Analytics (G-XXXX), Mixpanel tokens, LaunchDarkly client IDs, reCAPTCHA site keys. They carry no administrative authority.
            <div class="triage-tag">Action: Auto-dropped (NA-KB)</div>
          </div>
          <div class="triage-item">
            <b>Standard 404s &amp; Public robots.txt</b>
            Normal web behavior. Discovering <code>/robots.txt</code> or standard error pages is recon context, not a vulnerability.
            <div class="triage-tag">Action: Indexed for crawl, not alerted</div>
          </div>
          <div class="triage-item">
            <b>Rate Limiting / 429 WAF blocks</b>
            Temporary rate-limiting responses. HushHunt backs off dynamically rather than mistaking them for security flaws.
            <div class="triage-tag">Action: Auto-throttled</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Actionable Live Signals -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Live Actionable Candidates</div>
          <div class="card-desc">Active signals undergoing AI triage &amp; verification</div>
        </div>
      </div>
      <div class="table-wrap">
        <table id="table-actionable">
          <thead>
            <tr><th>ID</th><th>Program</th><th>Check Vector</th><th>Severity</th><th>Target Asset</th></tr>
          </thead>
          <tbody><tr><td colspan="5" style="text-align:center;color:var(--text-muted)">Loading actionable items...</td></tr></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 3: Target & Scope Map -->
  <section class="tab-pane" id="tab-domains">
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Target Scopes &amp; Domain Map</div>
          <div class="card-desc">HackerOne &amp; Bugcrowd synchronized bug bounty programs</div>
        </div>
      </div>

      <div class="search-row">
        <input type="text" class="search-input" id="dom-search" placeholder="Search by domain, handle, or asset keyword (e.g. kucoin, api, sandbox)...">
        <div class="filter-pills">
          <button class="pill-btn active" data-filter="all">All (436)</button>
          <button class="pill-btn" data-filter="paid">Paid BBP Only ($1,000)</button>
          <button class="pill-btn" data-filter="active">Active Traffic</button>
        </div>
      </div>

      <div class="table-wrap">
        <table id="table-programs">
          <thead>
            <tr><th>Program Handle</th><th>Type</th><th>Requests</th><th>Signals</th><th>In-Scope Assets</th><th>Action</th></tr>
          </thead>
          <tbody><tr><td colspan="6" style="text-align:center;color:var(--text-muted)">Loading target programs...</td></tr></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB 4: Vulnerability Vault -->
  <section class="tab-pane" id="tab-vulns">
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Vulnerability &amp; Signal Vault</div>
          <div class="card-desc">Full archive of discovered anomalies, proofs of concept, and triage verdicts</div>
        </div>
      </div>
      <div class="table-wrap">
        <table id="table-vulns">
          <thead>
            <tr><th>Signal #</th><th>Program</th><th>Check</th><th>Severity</th><th>Asset</th><th>Stage</th></tr>
          </thead>
          <tbody><tr><td colspan="6" style="text-align:center;color:var(--text-muted)">Loading signal archive...</td></tr></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- TAB: Verified Bugs & Reports -->
  <section class="tab-pane" id="tab-bugs">
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Verified Vulnerabilities &amp; Submission Reports</div>
          <div class="card-desc">High-confidence findings confirmed exploitable with evidence and submission-ready markdown reports</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:360px 1fr;gap:20px;align-items:start;">
        <!-- Left: List of Verified Bugs -->
        <div id="verified-cards" style="display:flex;flex-direction:column;gap:12px;">
          <div style="color:var(--text-muted)">Loading verified findings...</div>
        </div>
        <!-- Right: Report Viewer -->
        <div class="card" style="margin-bottom:0;background:#050607;border:1px solid var(--border-subtle);min-height:500px;display:flex;flex-direction:column;">
          <div class="card-header" style="border-bottom:1px solid var(--border-subtle);padding-bottom:12px;margin-bottom:14px;">
            <div>
              <div class="card-title" id="rep-viewer-title">Select a verified finding</div>
              <div class="card-desc" id="rep-viewer-meta">Proof of Concept and submission report</div>
            </div>
            <button class="pill-btn" id="rep-copy-btn" style="display:none" onclick="copyActiveReport()">Copy Report</button>
          </div>
          <pre id="rep-viewer-body" style="font-family:var(--font-mono);font-size:12px;line-height:1.6;color:#c9d1d9;white-space:pre-wrap;overflow-y:auto;max-height:600px;flex:1;">Click any verified bug on the left to inspect its proof of concept, reproduction steps, and generated bounty report.</pre>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 5: AI Reasoning Feed -->
  <section class="tab-pane" id="tab-reasoning">
    <div class="card">
      <div class="card-header">
        <h3>Why AI Did What It Did</h3>
        <span class="card-subtitle" id="reasoning-count">Loading reasoning feed...</span>
      </div>
      <p style="color:var(--text-muted);font-size:13px;margin-top:0;">
        Every planner proposal and triager verdict below carries the model's own
        one-line rationale. Planner rows show approved tests and rejections;
        triage rows show why a signal was kept or dropped.
      </p>
      <div id="reasoning-feed" style="display:flex;flex-direction:column;gap:10px;">
        <div style="color:var(--text-muted)">Loading AI reasoning...</div>
      </div>
    </div>
  </section>

  <!-- TAB 6: Live Traffic & Console -->
  <section class="tab-pane" id="tab-live">
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Live Engine Console (var/paid_run.log)</div>
          <div class="card-desc">Instant real-time stream from the autonomous hunt daemon</div>
        </div>
        <div class="terminal-controls">
          <label><input type="checkbox" id="autoscroll-chk" checked> Auto-scroll to bottom</label>
        </div>
      </div>
      <pre class="terminal" id="terminal-out">Connecting to live run stream...</pre>
    </div>

    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Recent HTTP Traffic (Last 50 Probes)</div>
          <div class="card-desc">Active requests hitting in-scope endpoints</div>
        </div>
      </div>
      <div class="table-wrap">
        <table id="table-traffic">
          <thead>
            <tr><th>Status</th><th>Program</th><th>Time</th><th>Probed URL</th></tr>
          </thead>
          <tbody><tr><td colspan="4" style="text-align:center;color:var(--text-muted)">Loading live requests...</td></tr></tbody>
        </table>
      </div>
    </div>
  </section>

</main>

<script>
// Tab Switching
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const target = document.getElementById(btn.dataset.tab);
    if (target) target.classList.add('active');
  });
});

const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const SEV_BADGE = {
  high: 'badge badge-high',
  medium: 'badge badge-medium',
  low: 'badge badge-low',
  info: 'badge badge-info'
};
const STATUS_COLORS = {
  '2': '#10b981',
  '3': '#58a6ff',
  '4': '#d29922',
  '5': '#ff7b72'
};

// Global Store
let PROGRAMS = [];
let DOM_FILTER = 'all';

// 1. Instant Summary Poll (Every 2 seconds)
async function updateSummary() {
  try {
    const res = await fetch('/api/summary');
    if (!res.ok) return;
    const data = await res.json();
    const findings = data.findings || {};

    // KPIs
    document.getElementById('kpi-reqs').textContent = (data.total_requests || 0).toLocaleString();
    document.getElementById('kpi-signals').textContent = (data.total_signals || 0).toLocaleString();
    document.getElementById('kpi-verified').textContent = (findings.verified || 0).toLocaleString();
    document.getElementById('kpi-dropped').textContent = (findings.dropped || 0).toLocaleString();
    document.getElementById('kpi-reported').textContent = (findings.reported || 0) + ' reported to platform';

    if (data.llm_spend) {
      document.getElementById('kpi-spend').textContent = data.llm_spend;
    }
    if (data.last_request) {
      document.getElementById('kpi-last-target').textContent = 'Last: ' + data.last_request.program_id;
    }

    // Funnel
    document.getElementById('fn-reqs').textContent = (data.total_requests || 0).toLocaleString();
    document.getElementById('fn-sigs').textContent = (data.total_signals || 0).toLocaleString();
    document.getElementById('fn-noise').textContent = (findings.dropped || 0).toLocaleString();
    document.getElementById('fn-ver').textContent = (findings.verified || 0).toLocaleString();
    document.getElementById('fn-rep').textContent = (findings.reported || 0).toLocaleString();

    // Check type bars
    const bc = data.by_check || {};
    const maxVal = Math.max(1, ...Object.values(bc));
    const sortedChecks = Object.entries(bc).sort((a, b) => b[1] - a[1]);
    document.getElementById('bars-view').innerHTML = sortedChecks.map(([k, v]) => `
      <div class="bar-item">
        <div class="bar-label" title="${esc(k)}">${esc(k)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round(v / maxVal * 100)}%"></div></div>
        <div class="bar-val">${v}</div>
      </div>
    `).join('') || '<div style="color:var(--text-muted)">No checks recorded yet</div>';

    // Last ping
    const d = new Date();
    document.getElementById('last-ping').textContent = d.toTimeString().split(' ')[0];
  } catch (e) {
    document.getElementById('live-status').textContent = 'OFFLINE';
  }
}

// 2. Traffic Donut & Latency (Every 3.5 seconds)
async function updateTraffic() {
  try {
    const res = await fetch('/api/traffic');
    if (!res.ok) return;
    const t = await res.json();
    document.getElementById('donut-latency').textContent = `Avg Latency: ${t.avg_latency_ms || 0} ms`;

    const sc = t.status_codes || {};
    const total = Object.values(sc).reduce((a, b) => a + b, 0) || 1;
    let a0 = 0, svg = '';
    const sorted = Object.entries(sc).sort();

    for (const [code, n] of sorted) {
      const frac = n / total;
      const a1 = a0 + frac * 2 * Math.PI;
      const x0 = 50 + 40 * Math.cos(a0), y0 = 50 + 40 * Math.sin(a0);
      const x1 = 50 + 40 * Math.cos(a1), y1 = 50 + 40 * Math.sin(a1);
      const big = frac > 0.5 ? 1 : 0;
      const color = STATUS_COLORS[String(code)[0]] || '#888';
      svg += `<path d="M50,50 L${x0.toFixed(1)},${y0.toFixed(1)} A40,40 0 ${big},1 ${x1.toFixed(1)},${y1.toFixed(1)} Z" fill="${color}"/>`;
      a0 = a1;
    }

    const legend = sorted.map(([c, n]) => `
      <div class="legend-row">
        <div class="legend-dot" style="background:${STATUS_COLORS[String(c)[0]] || '#888'}"></div>
        <span style="font-family:var(--font-mono)">${c}</span>: <b>${n.toLocaleString()}</b>
        <span style="color:var(--text-muted)">(${Math.round(n / total * 100)}%)</span>
      </div>
    `).join('');

    document.getElementById('donut-view').innerHTML = `
      <svg width="120" height="120" viewBox="0 0 100 100">${svg}</svg>
      <div class="donut-legend">${legend}</div>
    `;
  } catch (e) {}
}

// 3. Live Console Streaming (Every 1.5 seconds)
async function updateConsole() {
  try {
    const res = await fetch('/api/log');
    if (!res.ok) return;
    const d = await res.json();
    const term = document.getElementById('terminal-out');
    const autoScroll = document.getElementById('autoscroll-chk').checked;
    if (d.lines && d.lines.length) {
      term.textContent = d.lines.join('\\n');
      if (autoScroll) {
        term.scrollTop = term.scrollHeight;
      }
    }
  } catch (e) {}
}

// 4. Recent Requests (Every 2.5 seconds)
async function updateRecent() {
  try {
    const res = await fetch('/api/recent');
    if (!res.ok) return;
    const rows = await res.json();
    const tbody = document.querySelector('#table-traffic tbody');
    tbody.innerHTML = rows.slice(0, 50).map(r => {
      const code = r.status || '?';
      const col = STATUS_COLORS[String(code)[0]] || '#888';
      return `
        <tr>
          <td><span class="badge" style="background:${col}22;color:${col}">${code}</span></td>
          <td><b>${esc(r.program_id)}</b></td>
          <td style="color:var(--text-muted);font-family:var(--font-mono)">${esc(r.ts ? r.ts.split('T')[1] : '')}</td>
          <td style="max-width:550px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono)" title="${esc(r.url)}">${esc(r.url)}</td>
        </tr>
      `;
    }).join('') || '<tr><td colspan="4">No requests logged yet</td></tr>';
  } catch (e) {}
}

// 5. Signals & Triage (Every 4 seconds)
async function updateSignals() {
  try {
    const res = await fetch('/api/signals');
    if (!res.ok) return;
    const s = await res.json();

    const renderRows = list => list.map(x => {
      const sev = (x.severity_hint || 'info').toLowerCase();
      const badgeCls = SEV_BADGE[sev] || SEV_BADGE.info;
      return `
        <tr>
          <td style="font-family:var(--font-mono)">#${x.id}</td>
          <td><b>${esc(x.program_id)}</b></td>
          <td style="font-family:var(--font-mono)">${esc(x.check_id)}</td>
          <td><span class="${badgeCls}">${esc(sev)}</span></td>
          <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono)" title="${esc(x.asset)}">${esc(x.asset)}</td>
        </tr>
      `;
    }).join('');

    document.querySelector('#table-actionable tbody').innerHTML =
      renderRows(s.actionable.slice(0, 40)) || '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">Zero actionable signals pending</td></tr>';

    document.querySelector('#table-vulns tbody').innerHTML =
      renderRows(s.actionable.slice(0, 80)) || '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">Vault empty</td></tr>';
  } catch (e) {}
}

// 6. Programs & Scope Map (Load once + search/filter)
async function loadPrograms() {
  try {
    const res = await fetch('/api/programs');
    if (!res.ok) return;
    PROGRAMS = await res.json();
    renderPrograms();
  } catch (e) {}
}

function renderPrograms() {
  const query = (document.getElementById('dom-search').value || '').toLowerCase().trim();
  const rows = PROGRAMS.filter(p => {
    if (DOM_FILTER === 'paid' && !p.max_bounty) return false;
    if (DOM_FILTER === 'active' && (!p.request_count || p.request_count === 0)) return false;
    if (!query) return true;
    const inScope = (p.includes || []).join(' ').toLowerCase();
    return p.id.toLowerCase().includes(query) || inScope.includes(query);
  });

  const tbody = document.querySelector('#table-programs tbody');
  tbody.innerHTML = rows.slice(0, 100).map(p => {
    const isPaid = !!p.max_bounty;
    const badge = isPaid
      ? `<span class="badge badge-paid">PAID $${p.max_bounty}</span>`
      : `<span class="badge badge-vdp">VDP</span>`;
    const scopePreview = (p.includes || []).slice(0, 3).join(', ') || 'Wildcard / API';
    return `
      <tr>
        <td><b>${esc(p.id)}</b></td>
        <td>${badge}</td>
        <td><b style="color:var(--text-primary)">${p.request_count || 0}</b></td>
        <td>${p.signal_count ? `<span class="badge badge-medium">${p.signal_count}</span>` : '0'}</td>
        <td style="max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono);color:var(--text-muted)" title="${esc(scopePreview)}">${esc(scopePreview)}</td>
        <td><a href="${esc(p.url || '#')}" target="_blank" rel="noopener">Open Scope ↗</a></td>
      </tr>
    `;
  }).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No matching programs found</td></tr>';
}

// Search and Filter Listeners
document.getElementById('dom-search').addEventListener('input', renderPrograms);
document.querySelectorAll('.filter-pills .pill-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-pills .pill-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    DOM_FILTER = btn.dataset.filter;
    renderPrograms();
  });
});

// 7. Verified Bugs & Reports
let VERIFIED_FINDINGS = [];
let ACTIVE_REPORT_TEXT = "";

async function updateVerified() {
  try {
    const res = await fetch('/api/verified');
    if (!res.ok) return;
    VERIFIED_FINDINGS = await res.json();
    renderVerified();
  } catch (e) {}
}

function renderVerified() {
  const container = document.getElementById('verified-cards');
  if (!container) return;
  if (!VERIFIED_FINDINGS.length) {
    container.innerHTML = '<div style="color:var(--text-muted);padding:14px;background:rgba(255,255,255,0.02);border-radius:6px;">No verified vulnerabilities logged yet.</div>';
    return;
  }
  container.innerHTML = VERIFIED_FINDINGS.map((f, idx) => {
    const sev = (f.severity_hint || 'high').toLowerCase();
    const badge = SEV_BADGE[sev] || SEV_BADGE.high;
    const stageBadge = f.stage === 'reported' ? 'badge badge-paid' : 'badge badge-low';
    return `
      <div class="card" style="padding:14px;cursor:pointer;transition:all 0.15s;" onclick="selectReport(${idx})" id="vcard-${f.id}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
          <b style="color:var(--text-primary);font-size:13px;">${esc(f.program_id)}</b>
          <div>
            <span class="${badge}">${esc(sev)}</span>
            <span class="${stageBadge}">${esc(f.stage)}</span>
          </div>
        </div>
        <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent-violet);margin-bottom:4px;">${esc(f.check_id)}</div>
        <div style="color:var(--text-muted);font-size:11px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono);">${esc(f.asset)}</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:11px;color:var(--text-muted);">
          <span>Confidence: <b>${Math.round((f.confidence || 1.0) * 100)}%</b></span>
          <span style="color:var(--accent-violet);font-weight:600;">View Report ↗</span>
        </div>
      </div>
    `;
  }).join('');
}

function selectReport(idx) {
  const f = VERIFIED_FINDINGS[idx];
  if (!f) return;
  document.querySelectorAll('#verified-cards .card').forEach(c => c.style.borderColor = 'var(--border-subtle)');
  const activeCard = document.getElementById('vcard-' + f.id);
  if (activeCard) activeCard.style.borderColor = 'var(--accent-violet)';

  document.getElementById('rep-viewer-title').textContent = `${f.check_id} — ${f.program_id}`;
  document.getElementById('rep-viewer-meta').textContent = `${f.stage.toUpperCase()} | Confidence: ${Math.round((f.confidence||1)*100)}% | Updated: ${f.updated_at || 'Recently'}`;
  
  ACTIVE_REPORT_TEXT = f.report_text || f.fallback_text || "No report markdown generated for this finding yet.";
  document.getElementById('rep-viewer-body').textContent = ACTIVE_REPORT_TEXT;
  document.getElementById('rep-copy-btn').style.display = 'inline-block';
}

function copyActiveReport() {
  if (!ACTIVE_REPORT_TEXT) return;
  navigator.clipboard.writeText(ACTIVE_REPORT_TEXT).then(() => {
    const btn = document.getElementById('rep-copy-btn');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

// 8. AI Reasoning Feed
async function updateReasoning() {
  try {
    const res = await fetch('/api/reasoning');
    if (!res.ok) return;
    const items = await res.json();
    const countEl = document.getElementById('reasoning-count');
    if (countEl) countEl.textContent = `${items.length} decisions logged`;
    const container = document.getElementById('reasoning-feed');
    if (!container) return;
    if (!items || items.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);padding:14px;background:rgba(255,255,255,0.02);border-radius:6px;">No AI decisions logged yet. Autonomous loop runs will stream rationales here.</div>';
      return;
    }
    container.innerHTML = items.map(r => {
      const isPlanner = r.source === 'planner';
      const badgeClass = isPlanner ? 'badge badge-paid' : 'badge badge-low';
      const approved = (r.verdict || '').includes('approved') || (r.verdict || '').includes('triaged');
      const verdStyle = approved ? 'color:var(--status-green);font-weight:600' : 'color:var(--text-muted)';
      const ts = r.timestamp ? (r.timestamp.split('T')[1]?.split('.')[0] || r.timestamp) : '';
      return `
        <div style="padding:12px 14px;background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);border-radius:6px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
            <div style="display:flex;align-items:center;gap:8px;">
              <span class="${badgeClass}">${esc(r.source.toUpperCase())}</span>
              <b style="color:var(--text-primary);font-size:13px;">${esc(r.program_id)}</b>
              <span style="font-family:var(--font-mono);font-size:11px;color:var(--accent-violet);">${esc(r.action)}</span>
            </div>
            <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${esc(ts)}</span>
          </div>
          <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);margin-bottom:6px;">Target: ${esc(r.target || 'N/A')} &nbsp;|&nbsp; Outcome: <span style="${verdStyle}">${esc(r.verdict)}</span></div>
          <div style="color:var(--text-primary);font-size:12px;line-height:1.4;background:rgba(0,0,0,0.25);padding:8px 10px;border-radius:4px;border-left:3px solid var(--accent-violet);">
            <b>Thought:</b> "${esc(r.rationale)}"
          </div>
        </div>
      `;
    }).join('');
  } catch (e) {
    console.error("Reasoning update failed:", e);
  }
}

// Initial boot
updateSummary();
updateTraffic();
updateConsole();
updateRecent();
updateSignals();
updateVerified();
updateReasoning();
loadPrograms();

// Direct instant update timers (No whole-page reload)
setInterval(updateSummary, 2000);
setInterval(updateConsole, 1500);
setInterval(updateRecent, 2500);
setInterval(updateTraffic, 3500);
setInterval(updateSignals, 4500);
setInterval(updateVerified, 4000);
setInterval(updateReasoning, 4000);
setInterval(loadPrograms, 30000);
</script>
</body>
</html>"""


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
def query_reasoning(db_path: str, limit: int = 100) -> list[dict]:
    """Return recent AI pentest decisions: planner rationale + triage reasoning."""
    conn = _ro(db_path)
    out: list[dict] = []
    try:
        try:
            p_rows = conn.execute(
                "SELECT program_id, module, url, param, why, verdict, created_at "
                "FROM planner_decisions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            for r in p_rows:
                out.append({
                    "timestamp": r["created_at"] or "",
                    "source": "planner",
                    "program_id": r["program_id"] or "",
                    "target": f"{r['url'] or ''} [{r['param'] or ''}]".strip(),
                    "action": f"Test {r['module'] or ''}",
                    "verdict": r["verdict"] or "",
                    "rationale": r["why"] or "",
                })
        except sqlite3.OperationalError:
            pass

        try:
            f_rows = conn.execute(
                "SELECT f.id, f.signal_id, f.stage, f.confidence, f.detail_json, f.updated_at, "
                "s.program_id, s.check_id, s.asset "
                "FROM findings f LEFT JOIN signals s ON s.id = f.signal_id "
                "ORDER BY f.id DESC LIMIT ?", (limit,)
            ).fetchall()
            for r in f_rows:
                try:
                    det = json.loads(r["detail_json"] or "{}")
                except Exception:
                    det = {}
                why = det.get("reasoning") or det.get("why") or det.get("reason") or ""
                if why:
                    out.append({
                        "timestamp": r["updated_at"] or "",
                        "source": "triage",
                        "program_id": r["program_id"] or "",
                        "target": r["asset"] or "",
                        "action": f"Triage {r['check_id'] or ''}",
                        "verdict": f"{r['stage']} ({int((r['confidence'] or 0)*100)}%)",
                        "rationale": why,
                    })
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()

    out.sort(key=lambda x: x["timestamp"], reverse=True)
    return out[:limit]


def query_api_routes(db_path: str, limit: int = 100) -> list[dict]:
    """Return API routes auto-discovered from OpenAPI/Swagger/GraphQL schemas."""
    conn = _ro(db_path)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT program_id, url, param, source, sample_url FROM params_seen "
            "WHERE source LIKE 'openapi%' OR source LIKE '%json%' OR source LIKE '%graphql%' "
            "ORDER BY rowid DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


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


def query_verified_findings(db_path: str) -> list[dict]:
    """Return verified/reported findings with joined signal context and report markdown text."""
    conn = _ro(db_path)
    try:
        rows = conn.execute(
            """SELECT f.id, f.signal_id, f.stage, f.confidence, f.report_path, f.outcome, f.updated_at,
                      s.program_id, s.asset, s.check_id, s.wstg, s.severity_hint
               FROM findings f
               LEFT JOIN signals s ON s.id = f.signal_id
               WHERE f.stage IN ('verified', 'reported')
               ORDER BY f.id DESC""",
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            item = dict(r)
            text: str | None = None
            rp = item.get("report_path")
            if rp:
                try:
                    text = pathlib.Path(rp).read_text(encoding="utf-8")[:20000]
                except OSError:
                    text = None
            item["report_text"] = text
            if text is None:
                item["fallback_text"] = (
                    f"**Title:** {item.get('check_id')} on {item.get('asset')}\n\n"
                    f"**Program:** {item.get('program_id')}\n"
                    f"**Stage:** {item.get('stage')} (confidence {item.get('confidence')})\n"
                    f"**Severity:** {item.get('severity_hint')}\n\n"
                    f"No markdown report file was generated for this finding yet. "
                    f"Use the evidence in var/evidence/ for manual triage."
                )
            out.append(item)
        return out
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
            elif self.path == "/api/verified":
                self._json(query_verified_findings(db))
            elif self.path == "/api/api-routes":
                self._json(query_api_routes(db))
            elif self.path == "/api/reasoning":
                self._json(query_reasoning(db))
            else:
                self.send_response(404)
                self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    return srv, srv.server_address[1]
