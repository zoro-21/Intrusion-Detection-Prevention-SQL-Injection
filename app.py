from flask import Flask, render_template, request, redirect, url_for, g
import sqlite3, os, datetime, re
from idps.engine import inspect_input, init_patterns

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "app.sqlite")

app = Flask(__name__)
patterns = init_patterns()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with open(os.path.join(os.path.dirname(__file__), "db", "schema.sql"), "r") as f:
        db.executescript(f.read())
    db.commit()

def seed_db():
    db = get_db()
    with open(os.path.join(os.path.dirname(__file__), "db", "seed.sql"), "r") as f:
        db.executescript(f.read())
    db.commit()

def log_security(event):
    db = get_db()
    db.execute(
        "INSERT INTO security_logs(ts, ip, endpoint, payload, action, reasons) VALUES (?, ?, ?, ?, ?, ?)",
        (
            datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z",
            request.remote_addr or "-",
            request.path,
            event.get("payload", ""),
            event.get("action", ""),
            "; ".join(event.get("reasons", []))
        ),
    )
    db.commit()

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    blocked = None
    reasons = []
    q = ""
    if request.method == "POST":
        q = request.form.get("q", "")

        verdict = inspect_input(q, patterns, context="search")
        if verdict["malicious"]:
            log_security({
                "payload": q,
                "action": "blocked",
                "reasons": verdict["reasons"],
            })
            blocked = True
            reasons = verdict["reasons"]
        else:
            # SAFE: parameterized query (prevents SQL injection)
            db = get_db()
            cursor = db.execute(
                "SELECT id, username, email FROM users WHERE username LIKE ?",
                (f"%{q}%",)
            )
            results = cursor.fetchall()
            log_security({
                "payload": q,
                "action": "allowed",
                "reasons": verdict["reasons"],
            })

    return render_template("index.html", results=results, blocked=blocked, reasons=reasons, q=q)

@app.route("/admin/logs")
def admin_logs():
    db = get_db()
    rows = db.execute(
        "SELECT id, ts, ip, endpoint, payload, action, reasons FROM security_logs ORDER BY id DESC LIMIT 250"
    ).fetchall()
    return render_template("admin.html", logs=rows)

@app.route("/seed")
def seed():
    # create DB if missing
    if not os.path.exists(DB_PATH):
        init_db()
    # seed demo data
    seed_db()
    return redirect(url_for("index"))

if __name__ == "__main__":
    # if DB doesn't exist, initialize schema
    if not os.path.exists(DB_PATH):
        with app.app_context():
            init_db()
    app.run(debug=True)
