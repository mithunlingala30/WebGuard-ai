"""Flask-SocketIO events: authenticated live scan updates."""
from flask_login import current_user
from flask_socketio import emit, join_room

from database import socketio
from models import Scan


@socketio.on("connect")
def on_connect():
    if not current_user.is_authenticated:
        return False                       # reject anonymous sockets
    join_room(f"user_{current_user.id}")   # receives scan_finished notifications


@socketio.on("subscribe_scan")
def on_subscribe(data):
    try:
        sid = int((data or {}).get("scan_id"))
    except (TypeError, ValueError):
        return
    scan = Scan.query.filter_by(id=sid, user_id=current_user.id).first()   # ownership check
    if scan:
        join_room(f"scan_{sid}")
        emit("scan_progress", scan.progress_payload())
