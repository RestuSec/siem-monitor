"""SIEM Monitor — masukin domain, langsung scan keamanan + log monitoring.

Cara pakai:
    python siem.py
    python siem.py --log /path/to/access.log

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
import os
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

DB_PATH = Path(__file__).parent / "siem.db"
DASHBOARD_PORT = 5000
LOG_PATH = None  # set via --log

CONFIG = {"domain": None, "interval": 30}
SCAN_HISTORY = []
REQUEST_LOG = []  # recent parsed requests for dashboard

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
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, ip TEXT, method TEXT, path TEXT, status INTEGER, attack TEXT
        );
    """)
    conn.close()

def _conn():
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=5)
    c.execute("PRAGMA journal_mode=WAL")
    return c

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
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cutoff = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    recent = db_query(
        "SELECT id FROM alerts WHERE rule=? AND ts >= ?",
        (rule, cutoff)
    )
    if recent:
        return
    db_exec(
        "INSERT INTO alerts (ts, rule, severity, message, score) VALUES (?, ?, ?, ?, ?)",
        (now_str, rule, severity, message, score)
    )
    icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "."}.get(severity, ".")
    print(f"  [{icon}] {severity}: {message}")

# ── AI Analysis (Groq) ────────────────────────────────────────────────────
GROQ_KEY = os.getenv("GROQ_API_KEY", "")

def ai_analyze(alerts):
    """Send alerts to Groq AI for analysis."""
    if not GROQ_KEY:
        return {"error": "No API key. Set GROQ_API_KEY env var."}
    if not alerts:
        return {"error": "No alerts to analyze."}

    alert_text = "\n".join(
        f"- [{a['severity']}] {a['rule']}: {a['message']} (at {a['ts']})"
        for a in alerts[:15]
    )
    prompt = (
        "You are a cybersecurity analyst. Analyze these security alerts and provide:\n"
        "1. Attack pattern summary (what's happening)\n"
        "2. Risk assessment (is this targeted or random?)\n"
        "3. Recommended actions (block IP, patch, etc.)\n"
        "4. Threat level (1-10)\n\n"
        f"Alerts:\n{alert_text}\n\n"
        "Respond in Indonesian, max 200 words."
    )
    payload = json.dumps({
        "model": "qwen/qwen3.6-27b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500,
        "temperature": 0.3,
    }).encode()
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {GROQ_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        text = data["choices"][0]["message"]["content"]
        return {"analysis": text, "model": data.get("model", "qwen/qwen3.6-27b")}
    except Exception as e:
        return {"error": str(e)}

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

    if status >= 500:
        log_event(domain, "headers", "SKIP", f"HTTP {status}, Cloudflare error page — no app headers", 0)
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
        ("/swagger/", "Swagger docs exposed"),
        ("/actuator", "Spring Actuator exposed"),
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

    # Check if server info leaked in headers (skip Cloudflare — it's expected)
    server = headers.get("Server", "")
    x_powered = headers.get("X-Powered-By", "")
    leaks = []
    if server and "cloudflare" not in server.lower():
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
    scores = {}
    scores["uptime"] = check_uptime(domain)
    scores["ssl"] = check_ssl(domain)
    scores["headers"] = check_headers(domain)
    scores["paths"] = check_paths(domain)
    total = sum(scores.values())
    SCAN_HISTORY.append({"ts": datetime.now().strftime("%H:%M:%S"), "score": min(100, total), **scores})
    if len(SCAN_HISTORY) > 30:
        SCAN_HISTORY.pop(0)
    return min(100, total)

def threat_level():
    """Calculate threat from recent alerts. Exponential decay — drops fast after attack stops."""
    cutoff = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    rows = db_query(
        "SELECT score, ts FROM alerts WHERE ts >= ? ORDER BY ts DESC",
        (cutoff,)
    )
    if not rows:
        return 0
    total = 0
    now = datetime.now()
    for r in rows:
        ts = datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S")
        age_min = (now - ts).total_seconds() / 60
        weight = 2.0 ** (-age_min)  # exponential: halves every minute
        total += r["score"] * weight
    return min(100, int(total))

# ── Log monitoring + attack detection ─────────────────────────────────────
# Paths our own scanner probes — skip these in attack detection
_SCANNER_PROBES = {"/.env","/.git/config","/wp-admin/","/admin/","/phpmyadmin/",
                   "/server-status","/server-info","/.htaccess","/backup/",
                   "/debug/","/swagger/","/actuator","/"}

ATTACK_PATTERNS = {
    "SQLI": re.compile(r"union\s+select|or\s+1\s*=\s*1|drop\s+table|--\s*$|select\s+\*|insert\s+into|delete\s+from|having\s+1|order\s+by\s+\d|waitfor\s+delay|sleep\(\d|benchmark\(|load_file|into\s+outfile",
                       re.I),
    "XSS": re.compile(r"<script|javascript:|on\w+\s*=|<img[^>]+onerror|<svg[^>]+onload|alert\s*\(|document\.cookie|document\.write|eval\s*\(",
                       re.I),
    "LFI": re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|/etc/shadow|/proc/self|file://|php://|expect://|input://|/var/log|/var/www",
                       re.I),
    "PATH_TRAVERSAL": re.compile(r"/\.\./|/\.\.\\|/\.\.%2f|/\.\.%5c", re.I),
    "ADMIN_SCAN": re.compile(r"/wp-admin|/phpmyadmin|/admin|/cpanel|/webmail|/cgi-bin|/phpinfo|/info\.php|/test\.php|/debug|/console",
                             re.I),
    "SENSITIVE_FILE": re.compile(r"/\.env|/\.git|/\.htaccess|/\.DS_Store|/config\.|/database\.|/backup|/dump\.sql|/composer\.json|/package\.json|/docker-compose|/Dockerfile|/wp-config|/xmlrpc",
                                 re.I),
}

# IP tracking for brute force detection
ip_request_times = {}  # {ip: [timestamp, ...]}

def detect_attack(ip, method, path, status):
    """Check request against attack patterns. Returns attack type or None."""
    text = f"{method} {path}"
    for name, pattern in ATTACK_PATTERNS.items():
        if pattern.search(text):
            return name
    # Method anomaly: PUT/DELETE/PATCH/TRACE/CONNECT
    if method in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT"):
        return "METHOD_ANOMALY"
    # Long URL: SQL injection combos, encoded payloads
    if len(path) > 100:
        return "LONG_URL"
    # Tool signatures in URL
    if re.search(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wfuzz|ffuf|havij|acunetix", path, re.I):
        return "TOOL_SCAN"
    # Flood: many same-path 401/403 = likely brute force or DDoS
    if status in (401, 403):
        recent = sum(1 for r in REQUEST_LOG[-50:] if r["ip"] == ip and r["path"] == path)
        if recent >= 5:
            return "FLOOD"
    if status >= 500:
        return "SERVER_ERR"
    return None

def log_request(ip, method, path, status, attack):
    db_exec(
        "INSERT INTO requests (ts, ip, method, path, status, attack) VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, method, path, status, attack)
    )
    # Only add to display buffer if NOT a scanner self-probe
    if path not in _SCANNER_PROBES:
        REQUEST_LOG.append({"ts": datetime.now().strftime("%H:%M:%S"), "ip": ip, "method": method, "path": path[:80], "status": status, "attack": attack})
        if len(REQUEST_LOG) > 200:
            REQUEST_LOG.pop(0)

def run_log_rules():
    """Analyze request log for attack patterns."""
    now = datetime.now()
    alerts = []

    # DDoS: >50 requests from same IP in 60s (exclude scanner self-probes)
    placeholders = ",".join("?" for _ in _SCANNER_PROBES)
    scan_params = list(_SCANNER_PROBES)
    rows = db_query(
        f"SELECT ip, COUNT(*) as cnt FROM requests WHERE ts >= ? AND path NOT IN ({placeholders}) GROUP BY ip HAVING cnt >= 50",
        ((now - timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S"),) + tuple(scan_params)
    )
    for r in rows:
        alerts.append(("DDOS", "CRITICAL", f"DDoS dari {r['ip']}: {r['cnt']} requests/60s", 90))

    # Brute force: >10 requests from same IP in 60s (lower than DDoS, exclude scanner)
    rows = db_query(
        f"SELECT ip, COUNT(*) as cnt FROM requests WHERE ts >= ? AND path NOT IN ({placeholders}) GROUP BY ip HAVING cnt >= 10 AND cnt < 50",
        ((now - timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S"),) + tuple(scan_params)
    )
    for r in rows:
        alerts.append(("BRUTE_FORCE", "HIGH", f"Request flood dari {r['ip']}: {r['cnt']} requests/60s", 40))

    # Attack pattern detection
    rows = db_query(
        "SELECT ip, attack, COUNT(*) as cnt FROM requests WHERE attack IS NOT NULL AND ts >= ? GROUP BY ip, attack HAVING cnt >= 1",
        ((now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),)
    )
    severity_map = {"SQLI": "CRITICAL", "XSS": "HIGH", "LFI": "CRITICAL", "PATH_TRAVERSAL": "HIGH",
                    "ADMIN_SCAN": "MEDIUM", "SENSITIVE_FILE": "MEDIUM", "SERVER_ERR": "LOW",
                    "FLOOD": "HIGH", "METHOD_ANOMALY": "MEDIUM", "LONG_URL": "MEDIUM", "TOOL_SCAN": "HIGH"}
    score_map = {"SQLI": 80, "XSS": 60, "LFI": 80, "PATH_TRAVERSAL": 50,
                 "ADMIN_SCAN": 20, "SENSITIVE_FILE": 20, "SERVER_ERR": 10, "FLOOD": 50,
                 "METHOD_ANOMALY": 30, "LONG_URL": 40, "TOOL_SCAN": 60}
    for r in rows:
        sev = severity_map.get(r["attack"], "MEDIUM")
        score = score_map.get(r["attack"], 20)
        alerts.append((r["attack"], sev,
                       f"{r['attack']} dari {r['ip']}: {r['cnt']} requests/5min", score))

    # High error rate from same IP (exclude scanner)
    rows = db_query(
        f"SELECT ip, COUNT(*) as total, SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as bad FROM requests WHERE ts >= ? AND path NOT IN ({placeholders}) GROUP BY ip HAVING total >= 5 AND bad * 1.0 / total >= 0.7",
        ((now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),) + tuple(scan_params)
    )
    for r in rows:
        alerts.append(("ERROR_FLOOD", "MEDIUM", f"Error flood dari {r['ip']}: {r['bad']}/{r['total']} errors", 25))

    for rule, sev, msg, score in alerts:
        alert("local", rule, sev, msg, score)

    return alerts

# ── Uvicorn access log parser ─────────────────────────────────────────────
UVICORN_RE = re.compile(
    r'(?P<ip>\S+):\d+ - "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3})'
)

def watch_log():
    """Tail access.log, parse, detect attacks."""
    if not LOG_PATH:
        return
    p = Path(LOG_PATH)
    print(f"  Watching log: {p}")

    if p.exists():
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)

    while True:
        if not p.exists():
            time.sleep(1)
            continue
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                m = UVICORN_RE.search(line)
                if m:
                    ip = m.group("ip")
                    method = m.group("method")
                    path = m.group("path")
                    status = int(m.group("status"))
                    # Skip our own scanner probes
                    attack = None if path in _SCANNER_PROBES else detect_attack(ip, method, path, status)
                    log_request(ip, method, path, status, attack)
                    if attack and attack != "SERVER_ERR":
                        print(f"  [!] {attack}: {ip} {method} {path} → {status}")

# Run log rules on a timer (every 15s), not modulo-based
def log_rules_loop():
    while True:
        time.sleep(15)
        try:
            run_log_rules()
        except Exception:
            pass

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
body{font-family:'Courier New',monospace;background:#0a0a1a;color:#e0e0e0;min-height:100vh}
.hdr{background:linear-gradient(135deg,#0d1117,#161b22);padding:14px 20px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #30363d}
.hdr h1{color:#00ff88;font-size:16px;letter-spacing:2px}
.hdr .status{font-size:11px;color:#8b949e}
.ct{max-width:1200px;margin:0 auto;padding:16px}
.row{display:grid;gap:12px;margin-bottom:12px}
.r3{grid-template-columns:280px 1fr 1fr}
.r2{grid-template-columns:1fr 1fr}
.r4{grid-template-columns:1fr 1fr 1fr 1fr}
.c{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;overflow:hidden}
.c h2{color:#58a6ff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #21262d}
.c h3{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.s{font-size:28px;font-weight:bold;color:#00ff88;line-height:1}
.sl{font-size:10px;color:#8b949e;margin-top:3px}
.fw{grid-column:1/-1}

/* Threat ring */
.ring{text-align:center;padding:15px 0}
.r{width:130px;height:130px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;position:relative}
.r::before{content:'';position:absolute;inset:-6px;border-radius:50%;border:2px solid #21262d}
.ri{width:104px;height:104px;border-radius:50%;background:#0d1117;display:flex;align-items:center;justify-content:center;flex-direction:column}
.rv{font-size:32px;font-weight:bold}
.rl{font-size:10px;color:#8b949e;margin-top:2px}
.n{border:4px solid #00ff88;box-shadow:0 0 20px #00ff8833}.n .rv{color:#00ff88}
.e{border:4px solid #58a6ff;box-shadow:0 0 20px #58a6ff33}.e .rv{color:#58a6ff}
.w{border:4px solid #d29922;box-shadow:0 0 20px #d2992233}.w .rv{color:#d29922}
.cr{border:4px solid #f85149;box-shadow:0 0 20px #f8514933}.cr .rv{color:#f85149}

/* Category bars */
.cat-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.cat-label{width:70px;font-size:10px;color:#8b949e;text-transform:uppercase}
.cat-bar{flex:1;height:20px;background:#161b22;border-radius:4px;overflow:hidden;position:relative}
.cat-fill{height:100%;border-radius:4px;transition:width 0.6s ease}
.cat-val{font-size:11px;font-weight:bold;width:32px;text-align:right}

/* Response time chart */
.chart{display:flex;align-items:flex-end;gap:3px;height:80px;padding-top:8px}
.chart-bar{flex:1;min-width:0;background:linear-gradient(to top,#00ff8844,#00ff88);border-radius:2px 2px 0 0;transition:height 0.3s;position:relative}
.chart-bar:hover{opacity:0.8}
.chart-bar .tip{display:none;position:absolute;bottom:calc(100% + 4px);left:50%;transform:translateX(-50%);background:#1c2128;border:1px solid #30363d;padding:2px 6px;border-radius:4px;font-size:9px;white-space:nowrap;z-index:1}
.chart-bar:hover .tip{display:block}
.chart-labels{display:flex;justify-content:space-between;font-size:8px;color:#484f58;margin-top:4px}

/* Input */
.input-row{display:flex;gap:8px;margin-bottom:10px}
.input-row input{flex:1;background:#0d1117;border:1px solid #30363d;color:#e0e0e0;padding:10px 14px;border-radius:6px;font-family:monospace;font-size:13px}
.input-row input:focus{outline:none;border-color:#58a6ff}
.input-row button{background:#238636;color:#fff;border:none;padding:10px 20px;border-radius:6px;font-family:monospace;font-weight:bold;cursor:pointer;font-size:12px;text-transform:uppercase;letter-spacing:1px}
.input-row button:hover{background:#2ea043}
.btn-disconnect{background:#da3633 !important}.btn-disconnect:hover{background:#f85149 !important}
.conn-info{font-size:11px;color:#8b949e;margin-bottom:10px;padding:8px 12px;background:#0d1117;border:1px solid #21262d;border-radius:6px;display:flex;align-items:center;gap:8px}
.status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-on{background:#00ff88;box-shadow:0 0 6px #00ff88}.dot-off{background:#484f58}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #161b22}
th{color:#58a6ff;font-weight:normal;font-size:10px;text-transform:uppercase;letter-spacing:0.5px}
tr:hover{background:#161b22}
.ok{color:#3fb950}.err{color:#f85149}.warn{color:#d29922}
.sev-CRITICAL{color:#f85149;font-weight:bold}.sev-HIGH{color:#d29922}.sev-MEDIUM{color:#d29922}.sev-LOW{color:#8b949e}

/* Tags */
.tag{display:inline-block;padding:3px 8px;border-radius:4px;font-size:9px;font-weight:bold;margin:2px}
.tag-ok{background:#0d2818;color:#3fb950;border:1px solid #238636}
.tag-warn{background:#2d1d00;color:#d29922;border:1px solid #d2992266}
.tag-crit{background:#3d1114;color:#f85149;border:1px solid #f8514966}
.tag-info{background:#0c2d6b;color:#58a6ff;border:1px solid #58a6ff44}

/* Info grid */
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.info-item{padding:6px 8px;background:#161b22;border-radius:4px}
.info-item .ik{font-size:9px;color:#484f58;text-transform:uppercase}
.info-item .iv{font-size:12px;color:#e0e0e0;margin-top:2px}

/* Scan history mini chart */
.hist{display:flex;align-items:flex-end;gap:2px;height:40px}
.hist-bar{flex:1;min-width:2px;border-radius:1px 1px 0 0;transition:height 0.3s}
</style></head><body>
<div class="hdr">
  <h1>SIEM MONITOR</h1>
  <div class="status" id="hdrStatus">v2.0</div>
</div>
<div class="ct">
<div class="input-row">
  <input type="text" id="domain" placeholder="Masukin domain... (contoh: restusec.my.id)">
  <button onclick="connect()" id="btnConnect">SCAN</button>
</div>
<div class="conn-info" id="connInfo"><span class="status-dot dot-off"></span>Belum connect.</div>

<div class="row r3">
  <div class="c"><h2>Threat Level</h2><div class="ring"><div class="r n" id="ring"><div class="ri"><div class="rv" id="rv">0</div><div class="rl" id="rl">AMAN</div></div></div></div>
  <div style="margin-top:8px"><h3>Scan History</h3><div class="hist" id="histChart"></div></div></div>
  <div class="c"><h2>Security Score</h2><div id="catBars"></div></div>
  <div class="c"><h2>Domain Info</h2><div class="info-grid" id="infoGrid"><div class="info-item"><div class="ik">Status</div><div class="iv">—</div></div></div></div>
</div>

<div class="row r2">
  <div class="c"><h2>Response Time</h2><div class="chart" id="rtChart"></div><div class="chart-labels"><span>15 scans ago</span><span>now</span></div></div>
  <div class="c"><h2>Findings</h2><div id="findingsBox" style="display:flex;flex-wrap:wrap;gap:4px;max-height:120px;overflow-y:auto"></div></div>
</div>

<div class="row r2">
  <div class="c"><h2>Alerts</h2><div style="max-height:220px;overflow-y:auto"><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Message</th></tr></thead><tbody id="tal"></tbody></table></div></div>
  <div class="c"><h2>Request Log</h2><div style="max-height:220px;overflow-y:auto"><table><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>Attack</th></tr></thead><tbody id="treq"></tbody></table></div></div>
</div>

<div class="row r1" style="grid-template-columns:1fr">
  <div class="c"><h2>AI Analysis</h2>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <button onclick="aiAnalyze()" id="btnAI" style="background:#8957e5;color:#fff;border:none;padding:8px 16px;border-radius:6px;font-family:monospace;font-weight:bold;cursor:pointer;font-size:11px;text-transform:uppercase;letter-spacing:1px">Analyze with AI</button>
      <span id="aiStatus" style="font-size:10px;color:#8b949e">Click to analyze alerts with Groq AI</span>
    </div>
    <div id="aiResult" style="background:#161b22;border:1px solid #21262d;border-radius:6px;padding:12px;font-size:12px;color:#e0e0e0;white-space:pre-wrap;max-height:300px;overflow-y:auto;display:none"></div>
  </div>
</div>
</div>

<script>
function connect(){
  const d=document.getElementById("domain").value.trim();
  if(!d)return;
  document.getElementById("btnConnect").textContent="SCANNING...";
  document.getElementById("btnConnect").disabled=true;
  fetch("/api/connect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:d})}).then(r=>r.json()).then(()=>{
    setTimeout(()=>{document.getElementById("btnConnect").textContent="SCAN";document.getElementById("btnConnect").disabled=false;},3000);
  });
}
function disconnect(){
  fetch("/api/disconnect",{method:"POST"}).then(()=>u());
}
function barColor(v){return v>=70?"#3fb950":v>=40?"#d29922":v>=20?"#f85149":"#f85149"}
function u(){fetch("/api").then(r=>r.json()).then(d=>{
  // Connection info
  const ci=document.getElementById("connInfo");
  if(d.domain){
    ci.innerHTML="<span class='status-dot dot-on'></span>Monitoring: <b style='color:#e0e0e0'>"+d.domain+"</b> &mdash; every "+d.interval+"s &nbsp;<span style='float:right;cursor:pointer;color:#f85149;font-size:10px' onclick='disconnect()'>[disconnect]</span>";
    document.getElementById("domain").value=d.domain;
    document.getElementById("hdrStatus").textContent=d.domain+" | "+d.total_events+" events | "+d.total_alerts+" alerts";
  } else {
    ci.innerHTML="<span class='status-dot dot-off'></span>Belum connect.";
    document.getElementById("hdrStatus").textContent="v2.0";
  }

  // Threat ring
  const l=d.threat;
  const lvl=l>=70?"CRITICAL":l>=40?"WARNING":l>=20?"ELEVATED":"AMAN";
  const cls=lvl.toLowerCase();
  document.getElementById("ring").className="r "+(cls==="aman"?"n":cls==="elevated"?"e":cls==="warning"?"w":"cr");
  document.getElementById("rv").textContent=l;
  document.getElementById("rl").textContent=lvl;

  // Category bars
  const cats=d.category_scores||{};
  const catNames={uptime:"Uptime",ssl:"SSL",headers:"Headers",paths:"Paths"};
  document.getElementById("catBars").innerHTML=Object.keys(catNames).map(k=>{
    const v=cats[k]||0;
    const inv=100-v; // lower score = better for security
    return "<div class='cat-row'><div class='cat-label'>"+catNames[k]+"</div><div class='cat-bar'><div class='cat-fill' style='width:"+v+"%;background:"+barColor(v)+"'></div></div><div class='cat-val' style='color:"+barColor(v)+"'>"+v+"</div></div>";
  }).join("");

  // Info grid
  const ig=document.getElementById("infoGrid");
  ig.innerHTML="<div class='info-item'><div class='ik'>Uptime</div><div class='iv'>"+d.uptime+"</div></div>"+
    "<div class='info-item'><div class='ik'>Avg Latency</div><div class='iv'>"+d.avg_latency+"ms</div></div>"+
    "<div class='info-item'><div class='ik'>Events</div><div class='iv'>"+d.total_events+"</div></div>"+
    "<div class='info-item'><div class='ik'>Alerts</div><div class='iv'>"+d.total_alerts+"</div></div>";

  // Response time chart
  const rt=d.response_times||[];
  const maxMs=Math.max(...rt.map(r=>r.ms),1);
  document.getElementById("rtChart").innerHTML=rt.map(r=>{
    const h=Math.max(4,r.ms/maxMs*100);
    const c=r.ms>3000?"#f85149":r.ms>1000?"#d29922":"#3fb950";
    return "<div class='chart-bar' style='height:"+h+"%;background:linear-gradient(to top,"+c+"44,"+c+")'><div class='tip'>"+r.ms+"ms</div></div>";
  }).join("");

  // Findings
  document.getElementById("findingsBox").innerHTML=(d.findings||[]).map(f=>{
    const cls=f.result==="OK"?"tag-ok":f.result==="EXPOSED"||f.result==="DOWN"?"tag-crit":"tag-warn";
    return "<span class='tag "+cls+"'>"+f.check_type+": "+f.result+"</span>";
  }).join("")||"<span style='color:#484f58;font-size:11px'>No findings yet</span>";

  // Scan history mini chart (scores inverted: stored=problems, display=security)
  const sh=d.scan_history||[];
  const maxS=Math.max(...sh.map(s=>100-s.score),1);
  document.getElementById("histChart").innerHTML=sh.map(s=>{
    const sec=100-s.score;
    const h=Math.max(3,sec/maxS*100);
    return "<div class='hist-bar' style='height:"+h+"%;background:"+barColor(sec)+"' title='Score: "+sec+"'></div>";
  }).join("")||"";

  // Alerts table
  document.getElementById("tal").innerHTML=d.alerts.map(a=>"<tr><td style='white-space:nowrap'>"+a.ts+"</td><td class='sev-"+a.sev+"'>"+a.sev+"</td><td>"+a.rule+"</td><td style='color:#8b949e'>"+a.msg+"</td></tr>").join("")||"<tr><td colspan=4 style='color:#484f58'>No alerts</td></tr>";

  // Request log
  document.getElementById("treq").innerHTML=(d.request_log||[]).reverse().map(r=>{
    const c=r.attack?"err":r.status>=400?"warn":"ok";
    return "<tr><td style='white-space:nowrap'>"+r.ts+"</td><td>"+r.ip+"</td><td>"+r.method+"</td><td style='max-width:180px;overflow:hidden;text-overflow:ellipsis'>"+r.path+"</td><td class='"+c+"'>"+r.status+"</td>"+(r.attack?"<td class='err'><b>"+r.attack+"</b></td>":"<td style='color:#484f58'>-</td>")+"</tr>";
  }).join("")||"<tr><td colspan=6 style='color:#484f58'>No log file connected. Start with: python siem.py --log access.log</td></tr>";
});}
setInterval(u,3000);u();
function aiAnalyze(){
  const btn=document.getElementById("btnAI");
  const st=document.getElementById("aiStatus");
  const res=document.getElementById("aiResult");
  btn.disabled=true;btn.textContent="ANALYZING...";st.textContent="Sending alerts to AI...";
  fetch("/api/ai-analyze",{method:"POST"}).then(r=>r.json()).then(d=>{
    btn.disabled=false;btn.textContent="ANALYZE WITH AI";
    if(d.error){st.textContent="Error: "+d.error;res.style.display="none";}
    else{st.textContent="Model: "+d.model;res.textContent=d.analysis;res.style.display="block";}
  }).catch(e=>{btn.disabled=false;btn.textContent="ANALYZE WITH AI";st.textContent="Error: "+e;});
}
</script></body></html>"""

# ── HTTP Handler ──────────────────────────────────────────────────────────
def _get_category_scores(domain):
    cats = {}
    for cat in ("uptime", "ssl", "headers", "paths"):
        rows = db_query("SELECT score FROM events WHERE domain=? AND check_type=? ORDER BY id DESC LIMIT 1", (domain, cat))
        # Invert: stored score = problem count (0=good), display as security (100=good)
        raw = rows[0]["score"] if rows else 0
        cats[cat] = max(0, 100 - raw)
    return cats

def _get_response_times(domain):
    rows = db_query("SELECT ts, detail FROM events WHERE domain=? AND check_type='uptime' AND result != 'DOWN' ORDER BY id DESC LIMIT 15", (domain,))
    times = []
    for r in reversed(rows):
        m = re.search(r"(\d+)ms", r.get("detail", ""))
        times.append({"ts": r["ts"][-8:], "ms": int(m.group(1)) if m else 0})
    return times

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
                "scan_history": SCAN_HISTORY[-15:],
                "category_scores": _get_category_scores(domain),
                "response_times": _get_response_times(domain),
                "request_log": REQUEST_LOG[-100:],
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
        elif self.path == "/api/ai-analyze":
            alerts = db_query("SELECT ts, rule, severity, message FROM alerts ORDER BY id DESC LIMIT 15")
            result = ai_analyze(alerts)
            _json_resp(self, result)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

# ── Main ─────────────────────────────────────────────────────────────────
def main():
    global LOG_PATH
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--log" and i < len(sys.argv):
            LOG_PATH = sys.argv[i + 1]

    print("=" * 50)
    print("  SIEM MONITOR v4.0 — AI Powered")
    print("=" * 50)

    init_db()
    db_load_config()

    # Load recent requests from DB into display buffer (attacks first, then recent clean)
    for r in db_query("SELECT ts, ip, method, path, status, attack FROM requests WHERE attack IS NOT NULL AND attack NOT IN ('ADMIN_SCAN','SENSITIVE_FILE') ORDER BY id DESC LIMIT 50"):
        t = r["ts"][-8:] if r["ts"] else ""
        REQUEST_LOG.append({"ts": t, "ip": r["ip"], "method": r["method"],
                           "path": r["path"][:80], "status": r["status"], "attack": r["attack"]})
    for r in db_query("SELECT ts, ip, method, path, status, attack FROM requests WHERE attack IS NULL AND path NOT IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ORDER BY id DESC LIMIT 50",
                      tuple(_SCANNER_PROBES)):
        t = r["ts"][-8:] if r["ts"] else ""
        REQUEST_LOG.append({"ts": t, "ip": r["ip"], "method": r["method"],
                           "path": r["path"][:80], "status": r["status"], "attack": r["attack"]})

    # Run log rules once on startup to catch any backlog
    try:
        run_log_rules()
    except Exception:
        pass

    threading.Thread(target=monitor_loop, daemon=True).start()
    threading.Thread(target=run_dashboard, daemon=True).start()
    threading.Thread(target=log_rules_loop, daemon=True).start()
    if LOG_PATH:
        threading.Thread(target=watch_log, daemon=True).start()

    print(f"  Dashboard: http://localhost:{DASHBOARD_PORT}")
    if CONFIG["domain"]:
        print(f"  Monitoring: {CONFIG['domain']}")
    if LOG_PATH:
        print(f"  Log file: {LOG_PATH}")
    print("=" * 50)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")

def run_dashboard():
    server = ThreadedHTTPServer(("0.0.0.0", DASHBOARD_PORT), DashHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
