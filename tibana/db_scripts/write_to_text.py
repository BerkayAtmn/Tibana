#!/usr/bin/env python3
import os
import logging
import sqlite3
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, timedelta, timezone
load_dotenv()

# Config from env
BASE_DIR = Path('.').resolve()
DATA_DIR = BASE_DIR / 'data'
DB_PATH = DATA_DIR / 'alerts.db'
TXT_PATH = DATA_DIR / 'attacker_ips.txt'
RETENTION_DAYS = int(os.getenv('RETENTION_DAYS'))

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

def main():
    TXT_PATH.parent.mkdir(parents=True, exist_ok=True)

    if not DB_PATH.exists():
        log.error("Database not found at %s", DB_PATH)
        return

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()

            # Delete old data
            cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
            deleted = cur.execute("DELETE FROM alerts WHERE attack_time < ?", (cutoff,)).rowcount
            conn.commit()
            log.info("Deleted %d alerts older than %d days", deleted, RETENTION_DAYS)

            # Export unique IPs
            cur.execute("SELECT DISTINCT src_ip FROM alerts")
            ips = [row[0] for row in cur.fetchall()]
    except sqlite3.Error as e:
        log.error("SQLite error: %s", e)
        return

    try:
        with TXT_PATH.open('w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        log.info("Exported %d unique IPs to %s", len(ips), TXT_PATH)
    except IOError as e:
        log.error("Failed to write to %s: %s", TXT_PATH, e)

if __name__ == "__main__":
    main()