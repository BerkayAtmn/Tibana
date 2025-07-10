#!/usr/bin/env python3
import os
import logging
import sqlite3
from dotenv import load_dotenv
from datetime import datetime
from pathlib import Path
from pymisp import PyMISP, MISPEvent
load_dotenv()

# Config from env
BASE_DIR = Path('.').resolve()
DATA_DIR = BASE_DIR / 'data'
DB_PATH = DATA_DIR / 'alerts.db'
MISP_URL = os.getenv('MISP_URL')
MISP_API_KEY = os.getenv('MISP_API_KEY')
VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() in ('true', '1', 'yes')

# Logging Setup 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# Initialize PyMISP
try:
    misp = PyMISP(MISP_URL, MISP_API_KEY, VERIFY_SSL)
    log.info("PyMISP initialized (%s)", MISP_URL)
except Exception as e:
    log.error("Failed to initialize PyMISP: %s", e)
    exit(1)

def send_ip_event(ip, timestamp, alert_type='', sensor=''):
    """
    Create a MISP event for the given IP and attributes.
    """
    try:
        # normalize timestamp to Zulu
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        ts_zulu = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        event = MISPEvent()
        event.info = f"TPOT alert — {alert_type or 'unknown'}"
        event.add_attribute('ip-src', ip, comment='Attacker IP')
        event.add_attribute('datetime', ts_zulu, comment='Attack time')
        if alert_type:
            event.add_attribute('text', alert_type, comment='Alert type')
        if sensor:
            event.add_attribute('text', sensor, comment='Sensor')

        response = misp.add_event(event)
        if response and response.get('Event'):
            event_id = response['Event']['id']
            log.info("Sent %s → MISP Event #%s", ip, event_id)
        else:
            log.error("Unexpected response sending %s: %s", ip, response)
    except Exception as e:
        log.error("Error sending %s to MISP: %s", ip, e)

def main():
    if not DB_PATH.exists():
        log.error("Database not found at %s", DB_PATH)
        return

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute(
                "SELECT DISTINCT src_ip, attack_time, alert_type, sensor "
                "FROM alerts ORDER BY attack_time ASC"
            )
            rows = cur.fetchall()
    except sqlite3.Error as e:
        log.error("SQLite error: %s", e)
        return

    if not rows:
        log.info("No alerts to send.")
        return

    for src_ip, attack_time, alert_type, sensor in rows:
        send_ip_event(src_ip, attack_time, alert_type, sensor)

if __name__ == "__main__":
    main()