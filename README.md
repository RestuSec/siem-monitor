# SIEM Monitor v5.0

Real-time Security Information and Event Monitoring untuk website. Zero dependencies — Python stdlib only + Groq AI + Telegram.

![Security Score](https://img.shields.io/badge/Security_Score-100/100-3fb950?style=flat-square)
![Threat Level](https://img.shields.io/badge/Threat_Level-Real--Time-f85149?style=flat-square)
![AI Powered](https://img.shields.io/badge/AI-Groq-8957e5?style=flat-square&logo=ai&logoColor=white)
![Telegram](https://img.shields.io/badge/Telegram-Notifications-0088cc?style=flat-square&logo=telegram&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white)

## Demo

> Testing keamanan: SQL Injection, XSS, LFI, DDoS, Brute Force, Tool Scan, Method Anomaly — semua terdeteksi real-time.

<video src="demo.mp4" controls width="100%"></video>

>[Download Video](https://github.com/RestuSec/siem-monitor/releases/tag/v3.1)

## Fitur

| Feature | Detail |
|---------|--------|
| **12 Attack Types** | SQLI, XSS, LFI, PATH_TRAVERSAL, DDoS, BRUTE_FORCE, FLOOD, TOOL_SCAN, METHOD_ANOMALY, SENSITIVE_FILE, ADMIN_SCAN, SERVER_ERR |
| **External Scanner** | SSL/TLS check, security headers, sensitive path probing (tiap 30s) |
| **Log Monitoring** | Tails uvicorn access log, real-time attack detection |
| **AI Analysis** | Groq AI analisis alerts — attack pattern, risk assessment, rekomendasi (otomatis tiap 2 menit) |
| **AI Chat** | Tanya jawab langsung sama AI soal keamanan website |
| **Telegram Notif** | Alert CRITICAL/HIGH otomatis dikirim ke Telegram lo |
| **Threat Level** | Exponential decay — naik saat serangan, turun otomatis setelah berhenti |
| **Dark Dashboard** | GitHub-style UI, live update tiap 3 detik |
| **Zero Dependencies** | Python stdlib only — `http.server`, `sqlite3`, `urllib`, `ssl`, `re` |
| **Persistent DB** | Config, alerts, requests survive restart (SQLite WAL mode) |

## Attack Detection

| Type | Severity | Trigger |
|------|----------|---------|
| `SQLI` | CRITICAL | `UNION SELECT`, `DROP TABLE`, `OR 1=1`, etc. |
| `LFI` | CRITICAL | `/etc/passwd`, `php://filter`, `file://`, `../` |
| `DDOS` | CRITICAL | >50 requests/60s dari IP yang sama |
| `XSS` | HIGH | `<script>`, `onerror=`, `javascript:`, `alert()` |
| `TOOL_SCAN` | HIGH | sqlmap, nikto, nmap, gobuster, ffuf, dll. di URL |
| `FLOOD` | HIGH | Repeated 401/403 pada path yang sama (5x+) |
| `BRUTE_FORCE` | HIGH | >10 requests/60s dari IP yang sama |
| `SERVER_ERR` | HIGH | HTTP 500+ responses |
| `METHOD_ANOMALY` | MEDIUM | PUT, DELETE, PATCH, TRACE requests |
| `ERROR_FLOOD` | MEDIUM | >70% error rate dari satu IP |
| `SENSITIVE_FILE` | MEDIUM | `/.env`, `/.git`, `/.htaccess`, `/backup/` |
| `ADMIN_SCAN` | MEDIUM | `/wp-admin`, `/phpmyadmin`, `/admin/`, `/debug/` |

## Quick Start

```bash
# Clone
git clone https://github.com/RestuSec/siem-monitor.git
cd siem-monitor

# Set environment variables (Windows PowerShell)
$env:GROQ_API_KEY="gsk_..."      # Groq AI (gratis)
$env:TELEGRAM_TOKEN="..."         # Telegram bot token
$env:TELEGRAM_CHAT_ID="..."       # Telegram chat ID

# Run dashboard only (external scanning)
python siem.py

# Run with log monitoring (attack detection dari access logs)
python siem.py --log /path/to/access.log
```

Buka **http://localhost:5000** → Connect → masukkan domain → klik **Analyze with AI** atau tanya langsung di **Chat dengan AI**.

## Setup Lengkap

### 1. Siapkan Website Server

Jalankan website lo dengan uvicorn/access logging aktif. Contoh wrapper `run_siem.py`:

```python
"""Run server with access logging for SIEM monitoring."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
from serve import app
import uvicorn

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port, access_log=True)
```

Redirect stderr ke file untuk log monitoring:

```bash
python run_siem.py 2> access.log
```

### 2. Jalankan SIEM

```bash
python siem.py --log access.log
```

### 3. Connect ke Dashboard

Buka **http://localhost:5000** → masukkan domain → SIEM mulai monitoring.

## Dashboard

```
┌─────────────────────────────────────────────────┐
│  SIEM MONITOR                                   │
│  restusec.my.id | 330 events | 9 alerts         │
├──────────────┬──────────────────────────────────┤
│ Threat Level │  Scan History    Security Score   │
│   73         │  ▓▓▓▓▓▓▓▓▓▓     Uptime:  100    │
│  CRITICAL    │  ▓▓▓▓▓▓▓▓▓▓     SSL:     100    │
│              │  ▓▓▓▓▓▓▓▓▓▓     Headers: 100    │
│              │  ▓▓▓▓▓▓▓▓▓▓     Paths:   100    │
├──────────────┼──────────────────────────────────┤
│ Domain Info  │  Response Time                    │
│ Uptime: 94%  │  ▁▂▃▄▅▆▇█▇▆▅▄▃▂▁               │
│ Latency: 152ms                                   │
├──────────────┴──────────────────────────────────┤
│  Alerts                                          │
│  [CRITICAL] SQLI: ...   [HIGH] XSS: ...          │
│  [CRITICAL] DDoS: ...   [HIGH] FLOOD: ...        │
├─────────────────────────────────────────────────┤
│  Request Log                                     │
│  Time  IP    Method  Path    Status  Attack      │
│  08:13 GET    /api?q=...  404  SQLI             │
│  08:13 GET    /?q=<scri.. 200  XSS              │
│  08:13 GET    /download?.. 404  LFI              │
└─────────────────────────────────────────────────┘
```

## Arsitektur

```
                    ┌──────────────┐
                    │   Website    │
                    │  (uvicorn)   │
                    └──────┬───────┘
                           │ access.log
                    ┌──────▼───────┐
                    │  SIEM Core   │
                    │              │
                    │ ┌──────────┐ │
                    │ │ Log Watch│─┤── Tail access.log
                    │ │          │ │   Parse & detect
                    │ └──────────┘ │
                    │ ┌──────────┐ │
                    │ │ Scanner  │─┤── SSL, Headers, Paths
                    │ │          │ │   tiap 30 detik
                    │ └──────────┘ │
                    │ ┌──────────┐ │
                    │ │ Alert    │─┤── Dedup 5 menit
                    │ │ Engine   │ │   Severity mapping
                    │ └──────────┘ │
                    │ ┌──────────┐ │
                    │ │ SQLite   │─┤── WAL mode
                    │ │ DB       │ │   Persistent
                    │ └──────────┘ │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Dashboard   │
                    │  :5000       │
                    │  Dark theme  │
                    │  Live 3s     │
                    └──────────────┘
```

## CLI

```
python siem.py                    # Dashboard + scanner only
python siem.py --log access.log   # Dashboard + scanner + log monitoring
```

## Config

Config tersimpan otomatis di SQLite (`siem.db`). Atau set manual:

```json
{
  "domain": "example.com",
  "interval": 30
}
```

## Tech Stack

- **Python 3.10+** — stdlib only, zero pip install
- **SQLite** — WAL mode untuk concurrent access
- **ThreadingHTTPServer** — non-blocking dashboard
- **regex** — 12 attack pattern matching
- **Cloudflare Tunnel** — optional, untuk expose website ke internet

## License

MIT
