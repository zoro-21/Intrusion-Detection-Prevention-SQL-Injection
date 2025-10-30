# Intrusion Detection & Prevention System (IDPS) — SQL Injection Demo

A lightweight, end-to-end demo project that **detects and blocks SQL Injection (SQLi)** attempts
while ensuring safe database access via **parameterized queries**.

## Features
- Rule-based + simple anomaly-based SQLi detection (regex, quote counts, suspicious tokens).
- Prevention: **prepared statements** (parameterized queries) to avoid SQL injection.
- Real-time blocking with request logging (IP, endpoint, payload, reasons).
- Admin dashboard to review logs.
- SQLite demo DB with sample users; Flask web UI for testing.

## Tech
- Python, Flask, SQLite
- Jinja2 templates
- Pure `sqlite3` (no ORM) for clarity

## Project Structure
```
idps-sqli/
├─ app.py
├─ requirements.txt
├─ README.md
├─ idps/
│  ├─ __init__.py
│  ├─ engine.py
│  └─ patterns.py
├─ db/
│  ├─ schema.sql
│  └─ seed.sql
├─ templates/
│  ├─ base.html
│  ├─ index.html
│  ├─ blocked.html
│  └─ admin.html
├─ static/
│  └─ styles.css
└─ tests/
   └─ test_engine.py
```

## Quickstart

### 1) Set up environment
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Initialize DB
`app.py` will auto-create tables on first run. You can seed demo users by visiting:
```
http://localhost:5000/seed
```

### 3) Run
```bash
python app.py
# open http://localhost:5000
```

### 4) Try it
- Safe example: `ali` (search users by name)
- Malicious example: `ali' OR 1=1 --` (should be blocked and logged)
### Notes
This demo is intentionally compact for learning. Extend with:
- Richer rule sets, payload sanitization, and ML-based classifiers.
- Email/SMS alerting when repeated attacks occur.
- Reverse proxy/WAF deployment in front of multiple apps.
