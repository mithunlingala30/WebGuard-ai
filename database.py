"""Shared extension objects and small database helpers."""
import sqlite3
from datetime import datetime, timezone

from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()


def utcnow():
    """Naive UTC timestamp (stored in SQLite as UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    """ISO-8601 string with a Z suffix so browsers parse it as UTC."""
    return dt.isoformat() + "Z" if dt else None


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, _record):
    """Enforce foreign keys and make concurrent scan threads cooperate."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()
