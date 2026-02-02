import sqlite3
from fastapi import HTTPException
from typing import Optional

DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
CREATE TABLE IF NOT EXISTS users (
                 username TEXT PRIMARY KEY,
                 hashed_password TEXT NOT NULL,
                 full_name TEXT
                 )
                 """)
    conn.commit()
    conn.close()

def get_user(username: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT username, hashed_password, full_name FROM users WHERE username = ?",
        (username, )
    ).fetchone()
    conn.close()
    if row:
        return {"username": row["username"], "hashed_password": row["hashed_password"], "full_name": row["full_name"]}
    return None

def create_user(username: str, hashed_password: str, full_name: str = ""):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO users (username, hashed_password, full_name) VALUES (?, ?, ?)",
            (username, hashed_password, full_name)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already taken")
    finally:
        conn.close()