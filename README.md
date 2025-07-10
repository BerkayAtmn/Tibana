### TIBANA - TPOT Alerts Automation Tool

Visual dashboard & tooling that turns raw TPOT/Elastic honeypot logs into actionable intel:

**Ingest →** fetches recent honeypot hits from Elasticsearch
**Normalize →** deduplicates & stores in local SQLite
**Visualize →** real‑time Flask+Tailwind+Chart.js dashboard
**Export →**
  * flat *attacker\_ips.txt* for block‑lists
  * one‑click push to MISP as properly‑typed events

---

## 1. Quick Start

```bash
# 1. clone & enter
$ git clone https://github.com/BerkayAtmn/Tibana.git

# 2. python env
$ python -m venv .venv && source .venv/bin/activate
$ pip install -r requirements.txt  # see below

# 3. configure
$ cp .env.example .env  # then edit

# 4. run dash (http://localhost:5000)
$ python run.py  # Flask dev server

# 5. pull latest alerts & send to MISP
$ python fetch_and_write.py   # → data/alerts.db
$ python write_to_misp.py     # optional; requires MISP creds
```

## 2. .env Variables

| key                       | purpose                               |
| ------------------------- | ------------------------------------- |
| `ELASTIC_HOST`            | URL of Elastic node with TPOT indexes |
| `RETENTION_DAYS`          | keep alerts window (ingest + cleanup) |
| `MISP_URL`/`MISP_API_KEY` | enable `write_to_misp.py`             |
| `FLASK_SECRET`            | session secret                        |

## 3. Repo Map

```
.
├─ fetch_and_write.py   # ingest: ES → SQLite
├─ write_to_text.py     # export: SQLite → attacker_ips.txt
├─ write_to_misp.py     # export: SQLite → MISP events
├─ run.py               # Flask UI & helper routes
├─ tibana/              # templates/, static/ (Tailwind, Chart.js)
│   ├─ templates/index.html
│   └─ static/{css/,js/}
└─ data/alerts.db       # auto‑created, persisted
```

## 4. Dependencies

* Python 3.9+
* pip packages: `flask`, `dotenv`, `elasticsearch`, `pymisp`
* Elasticsearch cluster with TPOT indices (`logstash-*`)
* (Opt) MISP 2.4+ with API key

A ready‑made **requirements.txt** is included.

## 5. License & Security

MIT License — do what you want, no warranty or guarantees. Use at your own risk.
