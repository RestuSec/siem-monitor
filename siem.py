"""SIEM Monitor — masukin domain, langsung monitor.

Cara pakai:
    python siem.py

Dashboard: http://localhost:5000
"""

import sqlite3
import time
import sys
import json
import threading
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

DB_PATH = Path(__file__).parent / "siem.db"
DASHBOARD_PORT = 5000

# In-memory config
CONFIG = {"domain": None, "interval": 10}

# ── DB ───────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, domain TEXT, status INTEGER, latency_ms INTEGER, error TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, rule TEXT, severity TEXT, message TEXT
        );
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY, value TEXT
        );
    """)
    conn.close()

def _conn():
    return sqlite3.connect(str(DB_PATH), check_same_thread=False)

def db_exec(sql, params=()):
    conn = _conn()
    conn.execute(sql, params)
    conn.commit()
    conn.close()

def db_query(sql, params=()):
    conn = _conn()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
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

# ── Probe ────────────────────────────────────────────────────────────────
def probe(domain):
    """Hit domain, return (status, latency_ms, error_str)."""
    url = f"https://{domain}" if "://" not in domain else domain
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        start = time.monotonic()
        req = urllib.request.Request(url, headers={"User-Agent": "SIEM-Monitor/1.0"})
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        ms = int((time.monotonic() - start) * 1000)
        return resp.status, ms, None
    except urllib.error.HTTPError as e:
        ms = int((time.monotonic() - start) * 1000)
        return e.code, ms, str(e)
    except Exception as e:
        return 0, 0, str(e)[:200]

# ── Rules ────────────────────────────────────────────────────────────────
def run_rules(domain):
    now = datetime.now()
    alerts = []

    # Down: 3 consecutive failures
    rows = db_query(
        "SELECT COUNT(*) as cnt FROM (SELECT status FROM events WHERE domain=? AND ts>=? ORDER BY id DESC LIMIT 3)",
        (domain, (now - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"))
    )
    if rows and rows[0]["cnt"] >= 3:
        last3 = db_query(
            "SELECT status FROM events WHERE domain=? AND ts>=? ORDER BY id DESC LIMIT 3",
            (domain, (now - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"))
        )
        if all(r["status"] == 0 for r in last3):
            alerts.append(("SITE_DOWN", "CRITICAL", f"{domain} down — 3 gagal berturut-turut"))

    # Slow: avg latency > 3000ms in last 5 checks
    row = db_query(
        "SELECT AVG(latency_ms) as avg_ms FROM (SELECT latency_ms FROM events WHERE domain=? AND status!=0 AND ts>=? ORDER BY id DESC LIMIT 5)",
        (domain, (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"))
    )
    if row and row[0]["avg_ms"] and row[0]["avg_ms"] > 3000:
        alerts.append(("SITE_SLOW", "HIGH", f"{domain} lambat — avg {int(row[0]['avg_ms'])}ms"))

    # High error rate: >50% errors in last 10 checks
    row = db_query(
        "SELECT COUNT(*) as total, SUM(CASE WHEN status=0 OR status>=500 THEN 1 ELSE 0 END) as bad FROM events WHERE domain=? AND ts>=?",
        (domain, (now - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"))
    )
    if row and row[0]["total"] >= 5:
        ratio = (row[0]["bad"] or 0) / row[0]["total"]
        if ratio >= 0.5:
            alerts.append(("ERROR_SPIKE", "MEDIUM", f"{domain} — {ratio:.0%} error rate"))

    for rule, sev, msg in alerts:
        db_exec(
            "INSERT INTO alerts (ts, rule, severity, message) VALUES (?, ?, ?, ?)",
            (now.strftime("%Y-%m-%d %H:%M:%S"), rule, sev, msg)
        )

    return alerts

# ── Monitor loop ─────────────────────────────────────────────────────────
def monitor_loop():
    while True:
        domain = CONFIG["domain"]
        if not domain:
            time.sleep(2)
            continue

        status, ms, err = probe(domain)
        db_exec(
            "INSERT INTO events (ts, domain, status, latency_ms, error) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), domain, status, ms, err)
        )

        alerts = run_rules(domain)
        for rule, sev, msg in alerts:
            icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!"}.get(sev, ".")
            print(f"  [{icon}] {sev}: {msg}")

        time.sleep(CONFIG["interval"])

# ── Dashboard ────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SIEM Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:monospace;background:#0a0a1a;color:#e0e0e0}
.hdr{background:#111;padding:12px;text-align:center;border-bottom:2px solid #333}
.hdr h1{color:#00ff88;font-size:18px}
.ct{max-width:900px;margin:0 auto;padding:15px}
.g{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px}
.c{background:#111;border:1px solid #333;border-radius:8px;padding:12px}
.c h2{color:#00ff88;font-size:12px;margin-bottom:8px;border-bottom:1px solid #222;padding-bottom:6px}
.s{font-size:24px;font-weight:bold;color:#00ff88}
.sl{font-size:10px;color:#888;margin-top:2px}
.ring{text-align:center;padding:10px}
.r{width:100px;height:100px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center}
.ri{width:80px;height:80px;border-radius:50%;background:#111;display:flex;align-items:center;justify-content:center;flex-direction:column}
.rv{font-size:24px;font-weight:bold}
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
.ok{color:#00ff88}.err{color:#ff3333}.warn{color:#ffaa00}
.sev-CRITICAL{color:#ff3333;font-weight:bold}.sev-HIGH{color:#ff8800}.sev-MEDIUM{color:#ffaa00}
.input-row{display:flex;gap:8px;margin-bottom:12px}
.input-row input{flex:1;background:#111;border:1px solid #333;color:#e0e0e0;padding:8px 12px;border-radius:6px;font-family:monospace;font-size:13px}
.input-row input:focus{outline:none;border-color:#00ff88}
.input-row button{background:#00ff88;color:#0a0a1a;border:none;padding:8px 16px;border-radius:6px;font-family:monospace;font-weight:bold;cursor:pointer;font-size:13px}
.input-row button:hover{background:#00cc6a}
.btn-disconnect{background:#ff3333 !important;color:#fff !important}
.btn-disconnect:hover{background:#cc0000 !important}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot-on{background:#00ff88}.dot-off{background:#555}.dot-warn{background:#ffaa00}
.conn-info{font-size:11px;color:#888;margin-bottom:12px;padding:8px;background:#111;border:1px solid #222;border-radius:6px}
</style></head><body>
<div class="hdr"><h1>SIEM MONITOR</h1></div>
<div class="ct">
<div class="input-row">
  <input type="text" id="domain" placeholder="Masukin domain... (contoh: restusec.my.id)">
  <button onclick="connect()" id="btnConnect">CONNECT</button>
</div>
<div class="conn-info" id="connInfo"><span class="status-dot dot-off"></span>Belum connect. Masukin domain di atas.</div>

<div class="g">
<div class="c"><h2>Threat Level</h2><div class="ring"><div class="r n" id="ring"><div class="ri"><div class="rv" id="rv">0</div><div class="rl" id="rl">NORMAL</div></div></div></div></div>
<div class="c"><h2>Uptime</h2><div class="s" id="uptime">—</div><div class="sl">dari 100 checks terakhir</div></div>
<div class="c"><h2>Avg Latency</h2><div class="s" id="latency">—</div><div class="sl">ms (5 checks terakhir)</div></div>
</div>

<div class="c fw" style="margin-bottom:12px"><h2>Recent Events</h2>
<table><thead><tr><th>Time</th><th>Status</th><th>Latency</th><th>Error</th></tr></thead><tbody id="tev"></tbody></table></div>

<div class="c fw"><h2>Alerts</h2>
<table><thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Message</th></tr></thead><tbody id="tal"></tbody></table></div>
</div>

<script>
let connected = false;
function connect(){
  const d=document.getElementById("domain").value.trim();
  if(!d)return;
  fetch("/api/connect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:d})}).then(r=>r.json()).then(r=>{
    connected=true;
    document.getElementById("btnConnect").textContent="DISCONNECT";
    document.getElementById("btnConnect").className="btn-disconnect";
    document.getElementById("btnConnect").onclick=disconnect;
    document.getElementById("domain").value=d;
  });
}
function disconnect(){
  fetch("/api/disconnect",{method:"POST"}).then(()=>{
    connected=false;
    document.getElementById("btnConnect").textContent="CONNECT";
    document.getElementById("btnConnect").className="";
    document.getElementById("btnConnect").onclick=connect;
  });
}
function u(){fetch("/api").then(r=>r.json()).then(d=>{
  const ci=document.getElementById("connInfo");
  if(d.domain){
    ci.innerHTML="<span class='status-dot dot-on'></span>Connected: <b>"+d.domain+"</b> (setiap "+d.interval+" detik)";
    document.getElementById("domain").value=d.domain;
    connected=true;
    document.getElementById("btnConnect").textContent="DISCONNECT";
    document.getElementById("btnConnect").className="btn-disconnect";
    document.getElementById("btnConnect").onclick=disconnect;
  } else {
    ci.innerHTML="<span class='status-dot dot-off'></span>Belum connect. Masukin domain di atas.";
  }
  const l=d.threat,lvl=l>=70?"CRITICAL":l>=40?"WARNING":l>=20?"ELEVATED":"NORMAL";
  const cls=lvl.toLowerCase();
  document.getElementById("ring").className="r "+(cls==="normal"?"n":cls==="elevated"?"e":cls==="warning"?"w":"cr");
  document.getElementById("rv").textContent=l;document.getElementById("rl").textContent=lvl;
  document.getElementById("uptime").textContent=d.uptime;
  document.getElementById("latency").textContent=d.avg_latency;
  document.getElementById("tal").innerHTML=d.alerts.map(a=>"<tr><td>"+a.ts+"</td><td>"+a.rule+"</td><td class='sev-"+a.sev+"'>"+a.sev+"</td><td>"+a.msg+"</td></tr>").join("")||"<tr><td colspan=4 style='color:#555'>No alerts</td></tr>";
  document.getElementById("tev").innerHTML=d.events.map(e=>{
    const c=e.status>=200&&e.status<400?"ok":e.status>=500?"err":"warn";
    const sc=e.status===0?"DOWN":e.status;
    return "<tr><td>"+e.ts+"</td><td class='"+c+"'>"+sc+"</td><td>"+(e.latency_ms?e.latency_ms+"ms":"—")+"</td><td style='color:#666'>"+(e.error||"—")+"</td></tr>";
  }).join("")||"<tr><td colspan=4 style='color:#555'>No events yet</td></tr>";
});}
setInterval(u,2000);u();
</script></body></html>"""


class DashHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api":
            domain = CONFIG["domain"]
            events = db_query("SELECT * FROM events ORDER BY id DESC LIMIT 30") if domain else []
            alerts = db_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 20") if domain else []

            # Uptime
            if domain:
                row = db_query("SELECT COUNT(*) as total, SUM(CASE WHEN status>=200 AND status<400 THEN 1 ELSE 0 END) as ok FROM (SELECT status FROM events WHERE domain=? ORDER BY id DESC LIMIT 100)", (domain,))
                if row and row[0]["total"] > 0:
                    uptime = f"{round((row[0]['ok'] or 0) / row[0]['total'] * 100)}%"
                else:
                    uptime = "—"
                row2 = db_query("SELECT AVG(latency_ms) as avg_ms FROM (SELECT latency_ms FROM events WHERE domain=? AND status!=0 ORDER BY id DESC LIMIT 5)", (domain,))
                avg_lat = f"{int(row2[0]['avg_ms'])}" if row2 and row2[0]["avg_ms"] else "—"
            else:
                uptime = "—"
                avg_lat = "—"

            # Threat
            if domain:
                row = db_query("SELECT COUNT(*) as cnt FROM alerts WHERE ts >= datetime('now', '-5 minutes')")
                a_count = row[0]["cnt"] if row else 0
                row2 = db_query("SELECT COUNT(*) as cnt FROM events WHERE domain=? AND ts >= datetime('now', '-60 seconds')", (domain,))
                e_count = row2[0]["cnt"] if row2 else 0
                threat = min(100, min(50, e_count) + min(50, a_count * 20))
            else:
                threat = 0

            data = json.dumps({
                "domain": domain,
                "interval": CONFIG["interval"],
                "threat": threat,
                "uptime": uptime,
                "avg_latency": avg_lat,
                "events": [{"ts": e["ts"], "status": e["status"], "latency_ms": e["latency_ms"], "error": e["error"]} for e in events],
                "alerts": [{"ts": a["ts"], "rule": a["rule"], "sev": a["severity"], "msg": a["message"]} for a in alerts],
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data.encode())
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
                # Quick probe to verify
                status, ms, err = probe(domain)
                print(f"  Connected: {domain} (status={status}, {ms}ms)")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "status": status, "ms": ms}).encode())
                return

        elif self.path == "/api/disconnect":
            CONFIG["domain"] = None
            db_save_config()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

def run_dashboard():
    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashHandler)
    server.serve_forever()

# ── Main ─────────────────────────────────────────────────────────────────
def main():
    print("=" * 50)
    print("  SIEM MONITOR")
    print("=" * 50)

    init_db()
    db_load_config()

    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

    t2 = threading.Thread(target=run_dashboard, daemon=True)
    t2.start()

    print(f"  Dashboard: http://localhost:{DASHBOARD_PORT}")
    if CONFIG["domain"]:
        print(f"  Monitoring: {CONFIG['domain']}")
    print("=" * 50)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
