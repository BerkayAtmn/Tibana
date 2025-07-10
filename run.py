import os
import sqlite3
import sys
import subprocess
from pathlib import Path
from flask import Flask, g, render_template, jsonify, flash, redirect, url_for

# App & Config 
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH  = BASE_DIR / 'data' / 'alerts.db'
SCRIPTS_ROOT = BASE_DIR / 'tibana'

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / 'tibana' / 'templates'),
    static_folder=str(BASE_DIR / 'tibana' / 'static')
)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'replace_with_secure_random')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_type  TEXT,
                src_ip      TEXT,
                sensor      TEXT,
                attack_time TEXT,
                UNIQUE(alert_type, src_ip, sensor, attack_time)
            )
        """)

# init on startup
init_db()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def api_alerts():
    cur = get_db().execute(
        "SELECT alert_type, src_ip, sensor, attack_time "
        "FROM alerts ORDER BY attack_time DESC"
    )
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)

def run_script(rel_path, success_msg):
    script = SCRIPTS_ROOT / rel_path
    if not script.exists():
        flash(f"Script not found: {script}", 'error')
        return

    try:
        subprocess.run(
            [sys.executable, str(script)],
            cwd=str(BASE_DIR),
            check=True
        )
        flash(success_msg, 'success')
    except subprocess.CalledProcessError as e:
        flash(f"Error running {rel_path}: {e}", 'error')

@app.route('/run_fetch', methods=['POST'])
def run_fetch():
    run_script('client_scripts/fetch_and_write.py', 'fetch_and_write.py completed')
    return redirect(url_for('index'))

@app.route('/run_text', methods=['POST'])
def run_text():
    run_script('db_scripts/write_to_text.py', 'write_to_text.py completed')
    return redirect(url_for('index'))

@app.route('/run_misp', methods=['POST'])
def run_misp():
    run_script('db_scripts/write_to_misp.py', 'write_to_misp.py completed')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)