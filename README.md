# 🗼 The Watchtower

> A self-hosted cybersecurity monitoring tool built with FastAPI. Continuously scans your targets for open ports, CVE vulnerabilities, SSL/TLS issues, DNS/email security misconfigurations, and subdomain exposure — then generates professional PDF reports.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-ready-blue?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## ✨ Features

- **Automated Scanning** — Each target has its own configurable scan interval. Scans run automatically in the background.
- **Port & Service Detection** — Nmap-powered port scanning with service version fingerprinting and false-positive filtering.
- **CVE Vulnerability Matching** — Detects known CVEs via the Vulners Nmap script with CVSS scoring.
- **SSL/TLS Analysis** — Checks certificate validity, expiry dates, and TLS configuration.
- **Security Headers** — Analyzes HTTP security headers (HSTS, X-Frame-Options, CSP, etc.).
- **DNS & Email Security** — SPF and DMARC record validation to detect spoofing risks.
- **Subdomain Discovery** — Passive subdomain enumeration via [crt.sh](https://crt.sh) certificate logs with live DNS verification.
- **Scan History** — Stores up to 30 scans per target with side-by-side diff comparison.
- **PDF Reports** — Auto-generated dark-themed PDF reports with CVE tables, action items, and subdomain findings.
- **Telegram Notifications** — Instant alerts when critical CVEs or exploits are detected.
- **REST API** — Full JSON API with auto-generated Swagger docs at `/docs`.
- **Authentication** — Session-based login system with hashed passwords.

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, Python 3.12 |
| Database | SQLite + SQLModel |
| Scanner | Nmap + python-nmap + Vulners script |
| DNS | dnspython |
| Subdomain | crt.sh API |
| PDF | ReportLab |
| Frontend | Jinja2, Bootstrap 5, vanilla JS |
| Auth | itsdangerous (signed sessions) |
| Notifications | Telegram Bot API |
| Deployment | Docker + Docker Compose |

---

## 🚀 Getting Started

### Prerequisites

- [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/)

### 1. Clone the repository

```bash
git clone https://github.com/omerfarukbaysal04/the-watchtower.git
cd the-watchtower
```

### 2. Create the `.env` file

```bash
cp .env.example .env
```

Edit `.env` and fill in the required values:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your_hashed_password
SECRET_KEY=your_secret_key
TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

**Generate a password hash:**
```bash
docker run --rm python:3.12 sh -c \
  "pip install bcrypt -q && python -c \"import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())\""
```

**Generate a secret key:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Build and run

```bash
docker-compose up --build
```

### 4. Open the dashboard

Navigate to [http://localhost:8000](http://localhost:8000) and log in with your credentials.

---

## 📡 API Reference

All endpoints require an active session cookie (login via the web UI first). Auto-generated interactive docs are available at `/docs`.

### Get all targets

```http
GET /api/targets
```

Returns a list of all monitored targets with their current status.

**Response:**
```json
[
  {
    "id": 1,
    "name": "My Server",
    "url": "https://example.com",
    "status": "Aktif 🟢",
    "interval": 60,
    "ssl_days": 87,
    "open_ports": "80/nginx, 443/https",
    "last_check": "2026-02-28T17:10:00"
  }
]
```

---

### Get target details

```http
GET /api/targets/{id}
```

Returns full details including vulnerabilities and last error.

---

### Get scan history

```http
GET /api/targets/{id}/history
```

Returns the last 30 scan records for a target.

**Response:**
```json
[
  {
    "id": 12,
    "scanned_at": "2026-02-28T17:10:00",
    "status": "Aktif 🟢",
    "open_ports": "80/nginx, 443/https",
    "ssl_days": 87,
    "last_error": null
  }
]
```

---

### Trigger a manual scan

```http
POST /api/targets/{id}/scan
```

Immediately queues a scan for the specified target.

**Response:**
```json
{
  "message": "My Server için tarama başlatıldı.",
  "target_id": 1
}
```

---

## 📁 Project Structure

```
the-watchtower/
├── app/
│   ├── templates/
│   │   ├── dashboard.html
│   │   ├── history.html
│   │   └── login.html
│   └── static/
├── modules/
│   ├── scanner.py          # HTTP/SSL checks
│   ├── recon_scanner.py    # Nmap integration
│   ├── dns_scanner.py      # SPF/DMARC checks
│   ├── subdomain_scanner.py# crt.sh enumeration
│   ├── engine.py           # Scan scheduler & runner
│   ├── pdf_generator.py    # ReportLab PDF builder
│   ├── models.py           # SQLModel DB models
│   ├── database.py         # DB engine & session
│   └── reporter.py         # Telegram notifications
├── auth.py                 # Session auth
├── main.py                 # FastAPI app & routes
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## ⚠️ Disclaimer

This tool is intended for use on systems you own or have explicit permission to scan. Unauthorized scanning may be illegal. The author is not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
