# logger_utils.py
import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
JSONL_PATH = DATA_DIR / "interactions.jsonl"
SQLITE_PATH = DATA_DIR / "interactions.db"

def ensure_data_paths():
    DATA_DIR.mkdir(exist_ok=True)
    if not JSONL_PATH.exists():
        JSONL_PATH.touch()
    # init sqlite
    conn = sqlite3.connect(SQLITE_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS interactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        route TEXT,
        method TEXT,
        path TEXT,
        client_ip TEXT,
        user_agent TEXT,
        summary TEXT,
        raw JSON
    )
    """)
    conn.commit()
    conn.close()

def log_interaction(event: dict):
    # write JSONL
    try:
        with open(JSONL_PATH, "a", encoding="utf8") as fh:
            fh.write(json.dumps(event, default=str, ensure_ascii=False) + "\n")
    except Exception as e:
        print("Failed to write jsonl:", e)

    # add summary to sqlite (keeps primary fields indexed)
    try:
        conn = sqlite3.connect(SQLITE_PATH)
        c = conn.cursor()
        summary = event.get("raw_body") or json.dumps(event.get("form") or {})
        c.execute("""
            INSERT INTO interactions (timestamp, route, method, path, client_ip, user_agent, summary, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("route"),
            event.get("method"),
            event.get("path"),
            event.get("client_ip"),
            event.get("user_agent"),
            (summary[:200] if summary else None),
            json.dumps(event, default=str, ensure_ascii=False)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Failed to insert sqlite:", e)
