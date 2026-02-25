import sqlite3
from datetime import datetime

DB_NAME = "cybot.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        created_at TEXT
    )
    """)

    # Create messages table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        role TEXT,
        content TEXT,
        timestamp TEXT,
        FOREIGN KEY(session_id) REFERENCES sessions(id)
    )
    """)

    conn.commit()
    conn.close()


def create_session(title="New Chat"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    created_at = datetime.now().isoformat()

    cursor.execute(
        "INSERT INTO sessions (title, created_at) VALUES (?, ?)",
        (title, created_at)
    )

    session_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return session_id


def save_message(session_id, role, content):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    timestamp = datetime.now().isoformat()

    cursor.execute(
        "INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
        (session_id, role, content, timestamp)
    )

    conn.commit()
    conn.close()


def get_sessions():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id, title FROM sessions ORDER BY id DESC")
    sessions = cursor.fetchall()

    conn.close()
    return sessions


def get_messages(session_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT role, content FROM messages WHERE session_id=? ORDER BY id",
        (session_id,)
    )

    messages = cursor.fetchall()
    conn.close()

    return messages