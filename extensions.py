"""Shared Flask extension instances (kept here to avoid circular imports)."""
from flask_login import LoginManager
from flask_socketio import SocketIO

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "warning"

# "threading" works everywhere (including Windows) without eventlet/gevent.
socketio = SocketIO(async_mode="threading", ping_timeout=30, ping_interval=15)
