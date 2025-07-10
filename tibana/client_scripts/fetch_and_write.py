#!/usr/bin/env python3
import os
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from pathlib import Path
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, TransportError
load_dotenv()

# Config from env
BASE_DIR = Path('.').resolve()
DATA_DIR = BASE_DIR / 'data'
DB_PATH = DATA_DIR / 'alerts.db'

ELASTIC_HOST = os.getenv('ELASTIC_HOST')
INDEX_PATTERN = 'logstash-*'
BATCH_SIZE = 1000
SCROLL_TIMEOUT = '2m'
RETENTION_DAYS = int(os.getenv('RETENTION_DAYS'))

# Logging Setup 
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# DB Initialization
def init_db():
    DATA_DIR.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_type   TEXT,
                src_ip       TEXT,
                sensor       TEXT,
                attack_time  TEXT,
                UNIQUE(alert_type, src_ip, sensor, attack_time)
            )
        """)
        connection.executescript("""
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_ip   ON alerts(src_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(attack_time);
        """)
    log.debug("Database initialized or already existed at %s", DB_PATH)

# 
def main():
    init_db()

    # Remove older than RETENTION_DAYS
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
    with sqlite3.connect(DB_PATH) as connection:
        cur = connection.cursor()
        deleted = cur.execute(
            "DELETE FROM alerts WHERE attack_time < ?",
            (cutoff,)
        ).rowcount
        connection.commit()
    log.info("Purged %d rows older than %s", deleted, cutoff)

    # ES connect
    try:
        es = Elasticsearch(ELASTIC_HOST)
        if not es.ping():
            raise ConnectionError("ping failed")
        log.info("Connected to Elasticsearch at %s", ELASTIC_HOST)
    except Exception as e:
        log.error("ES connection failed: %s", e)
        return

    # scroll & insert
    total_processed = total_inserted = 0
    try:
        response = es.search(
            index = INDEX_PATTERN,
            body = {
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": [{"range": {"@timestamp": {"gte": f"now-{RETENTION_DAYS}d"}}}],
                        "should": [
                            {"wildcard": {"eventid.keyword": pot}}
                            for pot in [
                                "cowrie.*","dionaea.*","heralding.*","mailoney.*",
                                "log4pot.*","redishoneypot.*","beelzebub.*",
                                "ciscoasa.*","citrixhoneypot.*"
                            ]
                        ],
                        "minimum_should_match": 1
                    }
                }
            },
            size = BATCH_SIZE,
            scroll = SCROLL_TIMEOUT
        )
        sid, hits = response["_scroll_id"], response["hits"]["hits"]
        log.debug("Got %d initial hits", len(hits))

        with sqlite3.connect(DB_PATH) as connection:
            cur = connection.cursor()
            while hits:
                for hit in hits:
                    total_processed += 1
                    source = hit.get("_source", {})
                    event_id = source.get("eventid")
                    source_ip = source.get("src_ip") or source.get("src_ipaddr") or source.get("ip")
                    timestamp = source.get("@timestamp")
                    if not (event_id and source_ip and timestamp):
                        continue
                    # parse timestamp
                    try:
                        at = datetime.fromisoformat(timestamp.replace("Z","+00:00"))
                    except ValueError:
                        continue
                    sensor = (
                        source.get("sensor") or 
                        (source.get("host") or {}).get("name") or 
                        (source.get("beat") or {}).get("hostname") or 
                        "unknown"
                    )
                    cur.execute(
                        "INSERT OR IGNORE INTO alerts(alert_type, src_ip, sensor, attack_time) VALUES (?,?,?,?)",
                        (event_id, source_ip, sensor, at.isoformat())
                    )
                    if cur.rowcount:
                        total_inserted += 1

                log.info("Batch done: processed %d, inserted %d so far", total_processed, total_inserted)
                response = es.scroll(scroll_id=sid, scroll=SCROLL_TIMEOUT)
                sid, hits = response["_scroll_id"], response["hits"]["hits"]

            connection.commit()
        log.info("All done: %d processed, %d inserted", total_processed, total_inserted)

    except (ConnectionError, TransportError) as e:
        log.error("Scroll error: %s", e)
    except Exception:
        log.exception("Unexpected error during ingest")

if __name__ == "__main__":
    main()