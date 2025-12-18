# logger_utils.py
import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime

# -----------------------------
# DATA PATHS
# -----------------------------
DATA_DIR = Path("data")

JSONL_PATH = DATA_DIR / "interactions.jsonl"
SQLITE_PATH = DATA_DIR / "interactions.db"
RL_JSONL_PATH = DATA_DIR / "rl_decisions.jsonl"

# -----------------------------
# INIT STORAGE
# -----------------------------
def ensure_data_paths():
    DATA_DIR.mkdir(exist_ok=True)

    # Attacker interaction logs
    if not JSONL_PATH.exists():
        JSONL_PATH.touch()

    # RL decision logs
    if not RL_JSONL_PATH.exists():
        RL_JSONL_PATH.touch()

    # SQLite DB
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

# -----------------------------
# LOG ATTACKER INTERACTION
# -----------------------------
def log_interaction(event: dict):
    """
    Logs attacker interaction to:
    - JSONL file (full raw data)
    - SQLite DB (indexed summary)
    """

    # JSONL
    try:
        with open(JSONL_PATH, "a", encoding="utf8") as fh:
            fh.write(json.dumps(event, default=str, ensure_ascii=False) + "\n")
    except Exception as e:
        print("Failed to write jsonl:", e)

    # SQLite
    try:
        conn = sqlite3.connect(SQLITE_PATH)
        c = conn.cursor()

        summary = event.get("raw_body") or json.dumps(event.get("form") or {})
        c.execute("""
            INSERT INTO interactions (
                timestamp, route, method, path,
                client_ip, user_agent, summary, raw
            )
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

# -----------------------------
# LOG RL AGENT DECISION
# -----------------------------
def log_rl_decision(state, action, reward, q_values, meta=None):
    """
    Logs internal RL agent decision-making.
    This is CRITICAL for:
    - Debugging
    - Evaluation
    - Viva explanation
    """

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "state": list(state),
        "action": action,
        "reward": reward,
        "q_values": q_values,
        "meta": meta or {}
    }

    try:
        with open(RL_JSONL_PATH, "a", encoding="utf8") as fh:
            fh.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
    except Exception as e:
        print("Failed to write RL decision log:", e)
