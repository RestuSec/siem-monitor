"""SIEM Monitor — masukin domain, langsung scan keamanan.

Cara pakai:
    python siem.py

Dashboard: http://localhost:5000
"""

import sqlite3
import time
import sys
import json
import re
import threading
import urllib.request
import urllib.error
import ssl
import socket
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

DB_PATH = Path(__file__).parent / "siem.db"
DASHBOARD_PORT = 5000

CONFIG = {"domain": None, "interval": 30}

# ── DB ───────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, domain TEXT, check_type TEXT, result TEXT, detail TEXT, score INTEGER
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, rule TEXT, severity TEXT, message TEXT, score INTEGER
        );
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY, value TEXT
        );
    """)
    conn.close()

def _conn():
    return sqlite3.connect(str(DB_PATH), check_same_thread=False)

def db_exec(sql, params=()):
    c = _conn(); c.execute(sql, params); c.commit(); c.close()

def db_query(sql, params=()):
    c = _conn(); c.row_factory = sqlite3.Row
    rows = c.execute(sql, params).fetchall(); c.close()
    return [dict(r) for r in rows]

def db_save_config():
    db_exec("INSERT OR REPLACE INTO config (key, value) VALUES ('domain', ?)", (CONFIG["domain"] or "",))
    db_exec("INSERT OR REPLACE INTO config (key, value) VALUES ('interval', ?)", (str(CONFIG["interval"]),))

def db_load_config():
    for row in db_query("SELECT key, value FROM config"):
        if row["key"] == "domain" and row["value"]:
            CONFIG["domain"] = row["value"]
        elif row["key"] == "interval":
            CONFIG["interval"] = int(row["value"])

# ── Scanner ──────────────────────────────────────────────────────────────
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

HEADERS = {"User-Agent": "SIEM-Monitor/2.0", "Accept": "*/*"}

def _fetch(url, timeout=8):
    req = urllib.request.Request(url, headers=HEADERS)
    start = time.monotonic()
    resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
    ms = int((time.monotonic() - start) * 1000)
    body = resp.read(50000).decode("utf-8", errors="replace")
    return resp.status, resp.headers, body, ms

def _safe_fetch(url, timeout=8):
    try:
        return _fetch(url, timeout)
    except urllib.error.HTTPError as e:
        body = e.read(50000).decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, getattr(e, "headers", {}), body, 0
    except Exception:
        return 0, {}, "", 0

def log_event(domain, check_type, result, detail, score):
    db_exec(
        "INSERT INTO events (ts, domain, check_type, result, detail, score) VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, check_type, result, detail, score)
    )

def alert(domain, rule, severity, message, score):
    recent = db_query(
        "SELECT id FROM alerts WHERE rule=? AND ts >= datetime('now', '-5 minutes')",
        (rule,)
    )
    if recent:
        return
    db_exec(
        "INSERT INTO alerts (ts, rule, severity, message, score) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), rule, severity, message, score)
    )
    icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "."}.get(severity, ".")
    print(f"  [{icon}] {severity}: {message}")

# ── Checks ───────────────────────────────────────────────────────────────
def check_ssl(domain):
    """SSL cert check: expiry, issuer."""
    score = 0
    try:
        conn = socket.create_connection((domain, 443), timeout=5)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(conn, server_hostname=domain)
        cert = ssock.getpeercert()
        ssock.close()

        # Expiry
        not_after_str = cert.get("notAfter") or cert.get("not_after") or ""
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
        if not not_after_str:
            log_event(domain, "ssl", "OK", f"Cert OK, issuer: {issuer_name}", 0)
            return 0
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.utcnow()).days

        if days_left < 0:
            score = 100
            alert(domain, "SSL_EXPIRED", "CRITICAL", f"SSL cert EXPIRED {abs(days_left)} hari lalu", score)
        elif days_left < 7:
            score = 80
            alert(domain, "SSL_EXPIRING", "CRITICAL", f"SSL cert expired dalam {days_left} hari", score)
        elif days_left < 30:
            score = 30
            alert(domain, "SSL_EXPIRING", "HIGH", f"SSL cert expired dalam {days_left} hari", score)

        log_event(domain, "ssl", "OK" if days_left > 30 else "WARN",
                  f"Expires: {not_after.strftime('%Y-%m-%d')} ({days_left}d), Issuer: {issuer_name}", score)

    except Exception as e:
        score = 50
        log_event(domain, "ssl", "ERROR", str(e)[:100], score)
        alert(domain, "SSL_ERROR", "HIGH", f"SSL check gagal: {str(e)[:80]}", score)

    return score

def check_headers(domain):
    """Security headers check."""
    score = 0
    url = f"https://{domain}"
    status, headers, body, ms = _safe_fetch(url)

    if status == 0:
        log_event(domain, "headers", "SKIP", "Site unreachable", 0)
        return 0

    h = {k.lower(): v for k, v in headers.items()}
    missing = []
    present = []

    checks = [
        ("strict-transport-security", "HSTS", 20),
        ("x-frame-options", "X-Frame-Options", 15),
        ("x-content-type-options", "X-Content-Type-Options", 10),
        ("content-security-policy", "CSP", 15),
        ("x-xss-protection", "X-XSS-Protection", 5),
        ("referrer-policy", "Referrer-Policy", 5),
        ("permissions-policy", "Permissions-Policy", 5),
    ]

    for header, name, pts in checks:
        if header in h:
            present.append(name)
        else:
            missing.append(name)
            score += pts

    if missing:
        alert(domain, "MISSING_HEADERS", "MEDIUM" if score < 40 else "HIGH",
              f"Missing headers: {', '.join(missing)}", score)

    log_event(domain, "headers", "WARN" if missing else "OK",
              f"Present: {', '.join(present) or 'none'} | Missing: {', '.join(missing) or 'none'}", score)

    return score

def check_paths(domain):
    """Probe common sensitive paths."""
    score = 0
    paths = [
        ("/robots.txt", "robots.txt (info disclosure)"),
        ("/.env", ".env file exposed"),
        ("/.git/config", ".git directory exposed"),
        ("/wp-admin/", "WordPress admin exposed"),
        ("/admin/", "Admin panel accessible"),
        ("/phpmyadmin/", "phpMyAdmin exposed"),
        ("/server-status", "Apache server-status"),
        ("/server-info", "Apache server-info"),
        ("/.htaccess", ".htaccess file exposed"),
        ("/backup/", "Backup directory exposed"),
        ("/debug/", "Debug endpoint"),
        ("/api/", "API endpoint"),
        ("/swagger/", "Swagger docs exposed"),
        ("/actuator", "Spring Actuator exposed"),
        ("/.well-known/security.txt", "security.txt"),
    ]

    exposed = []
    for path, desc in paths:
        url = f"https://{domain}{path}"
        status, _, body, _ = _safe_fetch(url, timeout=5)
        if status == 200:
            # Check if it's real content, not generic 404
            if len(body) > 10 and "404" not in body[:200].lower():
                exposed.append(f"{path} ({status})")
                log_event(domain, "path_check", "EXPOSED", f"{path} → {status}", 10)

    if exposed:
        pts = min(60, len(exposed) * 10)
        score += pts
        sev = "CRITICAL" if any(p in ["/.env", "/.git/config", "/.htaccess"] for p in exposed) else "HIGH"
        alert(domain, "PATHS_EXPOSED", sev,
              f"{len(exposed)} sensitive paths accessible: {', '.join(exposed[:5])}", pts)
    else:
        log_event(domain, "path_check", "OK", f"Scanned {len(paths)} paths, none exposed", 0)

    return score

def check_uptime(domain):
    """Quick uptime + response check."""
    url = f"https://{domain}"
    status, headers, body, ms = _safe_fetch(url)

    if status == 0:
        alert(domain, "SITE_DOWN", "CRITICAL", f"{domain} unreachable", 50)
        log_event(domain, "uptime", "DOWN", "Connection failed", 50)
        return 50

    score = 0
    if status >= 500:
        score = 40
        alert(domain, "SERVER_ERROR", "HIGH", f"HTTP {status} response", score)

    if ms > 5000:
        score += 20
        alert(domain, "SLOW_RESPONSE", "MEDIUM", f"Response time {ms}ms", 20)

    # Check if server info leaked in headers
    server = headers.get("Server", "")
    x_powered = headers.get("X-Powered-By", "")
    leaks = []
    if server:
        leaks.append(f"Server: {server}")
    if x_powered:
        leaks.append(f"X-Powered-By: {x_powered}")
    if leaks:
        score += 5
        log_event(domain, "info_leak", "WARN", " | ".join(leaks), 5)

    log_event(domain, "uptime", "OK" if status < 400 else "WARN",
              f"HTTP {status} | {ms}ms", score)
    return score

# ── Full scan ────────────────────────────────────────────────────────────
def run_scan(domain):
    total = 0
    total += check_uptime(domain)
    total += check_ssl(domain)
    total += check_headers(domain)
    total += check_paths(domain)
    return min(100, total)

def threat_level():
    """Calculate threat from recent alerts. Newer = heavier."""
    rows = db_query(
        "SELECT score, ts FROM alerts WHERE ts >= datetime('now', '-10 minutes') ORDER BY ts DESC"
    )
    if not rows:
        return 0
    total = 0
    now = datetime.now()
    for i, r in enumerate(rows):
        ts = datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S")
        age_min = (now - ts).total_seconds() / 60
        weight = max(0.2, 1.0 - (age_min / 10))  # newer = higher weight
        total += r["score"] * weight
    # Normalize: divide by expected max (100 * avg ~5 alerts)
    return min(100, int(total / 3))

# ── Monitor loop ─────────────────────────────────────────────────────────
def monitor_loop():
    while True:
        domain = CONFIG["domain"]
        if not domain:
            time.sleep(2)
            continue

        print(f"  Scanning {domain}...")
        run_scan(domain)
        tl = threat_level()
        print(f"  Threat level: {tl}")

        time.sleep(CONFIG["interval"])

# ── Dashboard ────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SIEM Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:monospace;background:#0a0a1a;color:#e0e0e0}
.hdr{background:#111;padding:12px;text-align:center;border-bottom:2px solid #333}
.hdr h1{color:#00ff88;font-size:18px}
.ct{max-width:950px;margin:0 auto;padding:15px}
.g{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px}
.c{background:#111;border:1px solid #333;border-radius:8px;padding:12px}
.c h2{color:#00ff88;font-size:12px;margin-bottom:8px;border-bottom:1px solid #222;padding-bottom:6px}
.s{font-size:24px;font-weight:bold;color:#00ff88}
.sl{font-size:10px;color:#888;margin-top:2px}
.ring{text-align:center;padding:10px}
.r{width:110px;height:110px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center}
.ri{width:88px;height:88px;border-radius:50%;background:#111;display:flex;align-items:center;justify-content:center;flex-direction:column}
.rv{font-size:26px;font-weight:bold}
.rl{font-size:9px;color:#888;margin-top:2px}
.n{border:4px solid #00ff88}.n .rv{color:#00ff88}
.e{border:4px solid #00aaff}.e .rv{color:#00aaff}
.w{border:4px solid #ffaa00}.w .rv{color:#ffaa00}
.cr{border:4px solid #ff3333}.cr .rv{color:#ff3333}
.fw{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:5px 8px;text-align:left;border-bottom:1px solid #1a1a1a}
th{color:#00ff88;font-weight:normal}
tr:hover{background:#1a1a2e}
.ok{color:#00ff88}.err{color:#ff3333}.warn{color:#ffaa00}.info{color:#555}
.sev-CRITICAL{color:#ff3333;font-weight:bold}.sev-HIGH{color:#ff8800}.sev-MEDIUM{color:#ffaa00}.sev-LOW{color:#888}
.input-row{display:flex;gap:8px;margin-bottom:10px}
.input-row input{flex:1;background:#111;border:1px solid #333;color:#e0e0e0;padding:8px 12px;border-radius:6px;font-family:monospace;font-size:13px}
.input-row input:focus{outline:none;border-color:#00ff88}
.input-row button{background:#00ff88;color:#0a0a1a;border:none;padding:8px 16px;border-radius:6px;font-family:monospace;font-weight:bold;cursor:pointer;font-size:13px}
.input-row button:hover{background:#00cc6a}
.btn-disconnect{background:#ff3333 !important;color:#fff !important}
.conn-info{font-size:11px;color:#888;margin-bottom:10px;padding:8px;background:#111;border:1px solid #222;border-radius:6px}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot-on{background:#00ff88}.dot-off{background:#555}
.score-bar{height:14px;background:#222;border-radius:4px;margin-top:6px;overflow:hidden}
.score-fill{height:100%;border-radius:4px;transition:width 0.5s}
.findings{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.tag{padding:3px 8px;border-radius:4px;font-size:10px;font-weight:bold}
.tag-ok{background:#0a2a1a;color:#00ff88;border:1px solid #00ff8844}
.tag-warn{background:#2a1a0a;color:#ffaa00;border:1px solid #ffaa0044}
.tag-crit{background:#2a0a0a;color:#ff3333;border:1px solid #ff333344}
</style></head><body>
<div class="hdr"><h1>SIEM MONITOR</h1></div>
<div class="ct">
<div class="input-row">
  <input type="text" id="domain" placeholder="Masukin domain... (contoh: restusec.my.id)">
  <button onclick="connect()" id="btnConnect">SCAN</button>
</div>
<div class="conn-info" id="connInfo"><span class="status-dot dot-off"></span>Belum connect. Masukin domain di atas.</div>

<div class="g">
<div class="c"><h2>Threat Level</h2><div class="ring"><div class="r n" id="ring"><div class="ri"><div class="rv" id="rv">0</div><div class="rl" id="rl">AMAN</div></div></div></div></div>
<div class="c"><h2>Score Breakdown</h2><div class="findings" id="findings"></div><div class="score-bar"><div class="score-fill" id="scoreFill" style="width:0;background:#00ff88"></div></div><div class="sl" id="scoreText" style="margin-top:4px">—</div></div>
<div class="c"><h2>Info</h2><div style="font-size:11px;line-height:1.6" id="infoBox">—</div></div>
</div>

<div class="c fw" style="margin-bottom:12px"><h2>Security Findings</h2>
<table><thead><tr><th>Check</th><th>Result</th><th>Score</th><th>Detail</th></tr></thead><tbody id="tev"></tbody></table></div>

<div class="c fw"><h2>Alerts</h2>
<table><thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Message</th></tr></thead><tbody id="tal"></tbody></table></div>
</div>

<script>
function connect(){
  const d=document.getElementById("domain").value.trim();
  if(!d)return;
  document.getElementById("btnConnect").textContent="SCANNING...";
  document.getElementById("btnConnect").disabled=true;
  fetch("/api/connect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:d})}).then(r=>r.json()).then(()=>{
    setTimeout(()=>{document.getElementById("btnConnect").textContent="SCAN";document.getElementById("btnConnect").disabled=false;},2000);
  });
}
function disconnect(){
  fetch("/api/disconnect",{method:"POST"}).then(()=>u());
}
function u(){fetch("/api").then(r=>r.json()).then(d=>{
  const ci=document.getElementById("connInfo");
  if(d.domain){
    ci.innerHTML="<span class='status-dot dot-on'></span>Monitoring: <b>"+d.domain+"</b> (setiap "+d.interval+" detik) <span style='float:right;cursor:pointer;color:#ff5555' onclick='disconnect()'>[disconnect]</span>";
    document.getElementById("domain").value=d.domain;
  } else {
    ci.innerHTML="<span class='status-dot dot-off'></span>Belum connect. Masukin domain di atas.";
  }
  const l=d.threat;
  const lvl=l>=70?"CRITICAL":l>=40?"WARNING":l>=20?"ELEVATED":"AMAN";
  const cls=lvl.toLowerCase();
  document.getElementById("ring").className="r "+(cls==="aman"?"n":cls==="elevated"?"e":cls==="warning"?"w":"cr");
  document.getElementById("rv").textContent=l;
  document.getElementById("rl").textContent=lvl;
  document.getElementById("infoBox").innerHTML="<b>Domain:</b> "+(d.domain||"—")+"<br><b>Uptime:</b> "+d.uptime+"<br><b>Avg Latency:</b> "+d.avg_latency+"ms<br><b>Total Events:</b> "+d.total_events+"<br><b>Total Alerts:</b> "+d.total_alerts;
  const sf=document.getElementById("scoreFill");
  sf.style.width=l+"%";
  sf.style.background=l>=70?"#ff3333":l>=40?"#ffaa00":l>=20?"#00aaff":"#00ff88";
  document.getElementById("scoreText").textContent=l+"/100";
  document.getElementById("findings").innerHTML=d.findings.map(f=>{
    const cls=f.result==="OK"?"tag-ok":f.result==="EXPOSED"||f.result==="DOWN"?"tag-crit":"tag-warn";
    return "<span class='tag "+cls+"'>"+f.check_type+": "+f.result+" ("+f.score+")</span>";
  }).join("");
  document.getElementById("tal").innerHTML=d.alerts.map(a=>"<tr><td>"+a.ts+"</td><td>"+a.rule+"</td><td class='sev-"+a.sev+"'>"+a.sev+"</td><td>"+a.msg+"</td></tr>").join("")||"<tr><td colspan=4 style='color:#555'>No alerts</td></tr>";
  document.getElementById("tev").innerHTML=d.events.map(e=>{
    const c=e.result==="OK"?"ok":e.result==="EXPOSED"||e.result==="DOWN"?"err":"warn";
    return "<tr><td>"+e.check_type+"</td><td class='"+c+"'>"+e.result+"</td><td>"+e.score+"</td><td style='color:#888'>"+e.detail+"</td></tr>";
  }).join("")||"<tr><td colspan=4 style='color:#555'>No scan results yet</td></tr>";
});}
setInterval(u,3000);u();
</script></body></html>"""

# ── HTTP Handler ──────────────────────────────────────────────────────────
def _json_resp(handler, data):
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps(data).encode())

class DashHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api":
            domain = CONFIG["domain"]
            events = db_query("SELECT * FROM events WHERE domain=? ORDER BY id DESC LIMIT 20", (domain,)) if domain else []
            alerts = db_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 20") if domain else []
            findings = db_query("SELECT * FROM events WHERE domain=? AND check_type != 'uptime' ORDER BY id DESC LIMIT 20", (domain,)) if domain else []

            if domain:
                row = db_query("SELECT COUNT(*) as total, SUM(CASE WHEN result='OK' THEN 1 ELSE 0 END) as ok FROM events WHERE domain=? AND check_type='uptime'", (domain,))
                if row and row[0]["total"] > 0:
                    uptime = f"{round((row[0]['ok'] or 0) / row[0]['total'] * 100)}%"
                else:
                    uptime = "—"
                row2 = db_query("SELECT AVG(CAST(detail AS INTEGER)) as avg_ms FROM events WHERE domain=? AND check_type='uptime' AND result != 'DOWN' AND detail LIKE '%ms'", (domain,))
                avg_lat = "—"
                for r in db_query("SELECT detail FROM events WHERE domain=? AND check_type='uptime' ORDER BY id DESC LIMIT 5", (domain,)):
                    m = re.search(r"(\d+)ms", r.get("detail", ""))
                    if m:
                        avg_lat = m.group(1)
                        break
                total_e = db_query("SELECT COUNT(*) as c FROM events WHERE domain=?", (domain,))[0]["c"]
                total_a = db_query("SELECT COUNT(*) as c FROM alerts", ())[0]["c"]
            else:
                uptime = "—"; avg_lat = "—"; total_e = 0; total_a = 0

            _json_resp(self, {
                "domain": domain,
                "interval": CONFIG["interval"],
                "threat": threat_level(),
                "uptime": uptime,
                "avg_latency": avg_lat,
                "total_events": total_e,
                "total_alerts": total_a,
                "findings": [{"check_type": f["check_type"], "result": f["result"], "score": f["score"]} for f in findings],
                "events": [{"ts": e["ts"], "check_type": e["check_type"], "result": e["result"], "score": e["score"], "detail": e["detail"]} for e in events],
                "alerts": [{"ts": a["ts"], "rule": a["rule"], "sev": a["severity"], "msg": a["message"]} for a in alerts],
            })
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if self.path == "/api/connect":
            domain = body.get("domain", "").strip().strip("https://").strip("http://").rstrip("/")
            if domain:
                CONFIG["domain"] = domain
                db_save_config()
                threading.Thread(target=lambda: run_scan(domain), daemon=True).start()
                print(f"  Connected: {domain}")
                _json_resp(self, {"ok": True})
                return
        elif self.path == "/api/disconnect":
            CONFIG["domain"] = None
            db_save_config()
            _json_resp(self, {"ok": True})
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

# ── Main ─────────────────────────────────────────────────────────────────
def main():
    print("=" * 50)
    print("  SIEM MONITOR v2")
    print("=" * 50)

    init_db()
    db_load_config()

    threading.Thread(target=monitor_loop, daemon=True).start()
    threading.Thread(target=run_dashboard, daemon=True).start()

    print(f"  Dashboard: http://localhost:{DASHBOARD_PORT}")
    if CONFIG["domain"]:
        print(f"  Monitoring: {CONFIG['domain']}")
    print("=" * 50)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")

def run_dashboard():
    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
