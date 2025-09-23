import os
import time
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from flask import Flask, render_template, request, redirect, url_for, session as flask_session, flash, send_from_directory
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash


# -----------------------------
# Configuration
# -----------------------------

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
DEFAULT_ROOM = "0000"
ENABLE_SQLITE = os.environ.get("CHAT_USE_SQLITE", "1") == "1"
SQLITE_DB_PATH = os.environ.get("CHAT_SQLITE_PATH", os.path.join(os.path.dirname(__file__), "chat.db"))


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    return app


app = create_app()
# Use threading mode for broad Windows compatibility; can be overridden via env
ASYNC_MODE = os.environ.get("SOCKETIO_ASYNC", "threading")
socketio = SocketIO(app, async_mode=ASYNC_MODE, cors_allowed_origins="*")

login_manager = LoginManager(app)
login_manager.login_view = "login"


# -----------------------------
# In-memory state
# -----------------------------

# room -> list of message dicts {username, text, timestamp_iso}
room_messages: Dict[str, List[dict]] = {}

# room -> set of usernames
room_online_users: Dict[str, Set[str]] = {}

# username -> sid (latest)
username_to_sid: Dict[str, str] = {}

# Track online users and last seen
online_users: Set[str] = set()
last_seen_iso: Dict[str, str] = {}

# simple in-memory increasing id (per-process)
_last_message_id: int = int(time.time() * 1000)

# Reactions state: message_id -> username -> emoji
reactions_by_message: Dict[int, Dict[str, str]] = {}

# Groups: id -> {id, name, members:Set[str], messages:List[dict]}
groups: Dict[str, dict] = {}
# username -> set(group_id)
username_to_groups: Dict[str, Set[str]] = {}

# Media storage
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)


def generate_message_id() -> int:
    global _last_message_id
    _last_message_id += 1
    return _last_message_id


def generate_group_id() -> str:
    return f"g-{int(time.time()*1000)}"


# -----------------------------
# SQLite persistence (messages optional, users required)
# -----------------------------

# Adjusted to allow optional message_id for in-memory storage

def _sqlite_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _sqlite_init() -> None:
    conn = _sqlite_connect()
    try:
        # Users table (always available)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        # Add email column if missing
        try:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass
        # Messages table (optional usage gated by ENABLE_SQLITE)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room TEXT NOT NULL,
                username TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp_iso TEXT NOT NULL,
                message_id INTEGER
            );
            """
        )
        # Add message_id column if missing (for existing deployments)
        try:
            conn.execute("ALTER TABLE messages ADD COLUMN message_id INTEGER")
        except Exception:
            pass
        conn.commit()
    finally:
        conn.close()


def save_message(room: str, username: str, text: str, timestamp_iso: str, message_id: Optional[int] = None) -> None:
    if ENABLE_SQLITE:
        conn = _sqlite_connect()
        try:
            conn.execute(
                "INSERT INTO messages (room, username, text, timestamp_iso, message_id) VALUES (?, ?, ?, ?, ?)",
                (room, username, text, timestamp_iso, message_id),
            )
            conn.commit()
        finally:
            conn.close()
    else:
        room_messages.setdefault(room, []).append(
            {"username": username, "text": text, "timestamp_iso": timestamp_iso, "message_id": message_id}
        )
        # Keep only last 200 in memory per room to bound memory
        if len(room_messages[room]) > 200:
            room_messages[room] = room_messages[room][-200:]


def load_last_messages(room: str, limit: int = 50) -> List[dict]:
    if ENABLE_SQLITE:
        conn = _sqlite_connect()
        try:
            rows = conn.execute(
                "SELECT username, text, timestamp_iso, message_id FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?",
                (room, limit),
            ).fetchall()
            # reverse to oldest->newest
            return [
                {"username": r["username"], "text": r["text"], "timestamp_iso": r["timestamp_iso"], "message_id": r["message_id"]}
                for r in reversed(rows)
            ]
        finally:
            conn.close()
    else:
        return list(room_messages.get(room, []))[-limit:]


# -----------------------------
# Auth: User model and helpers
# -----------------------------

class User(UserMixin):
    def __init__(self, user_id: int, username: str, password_hash: str):
        self.id = str(user_id)
        self.username = username
        self.password_hash = password_hash


def get_user_by_id(user_id: str) -> Optional[User]:
    conn = _sqlite_connect()
    try:
        row = conn.execute("SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            return User(row["id"], row["username"], row["password_hash"])
        return None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[User]:
    conn = _sqlite_connect()
    try:
        row = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            return User(row["id"], row["username"], row["password_hash"])
        return None
    finally:
        conn.close()


def get_user_email(username: str) -> Optional[str]:
    conn = _sqlite_connect()
    try:
        row = conn.execute("SELECT email FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            return row["email"]
        return None
    finally:
        conn.close()


def create_user(username: str, password: str, email: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    username_n = normalize_username(username)
    if not username_n:
        return False, "Invalid username"
    if get_user_by_username(username_n):
        return False, "Username already exists"
    pw_hash = generate_password_hash(password)
    conn = _sqlite_connect()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at, email) VALUES (?, ?, ?, ?)",
            (username_n, pw_hash, now_iso(), (email or None)),
        )
        conn.commit()
        return True, None
    finally:
        conn.close()


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return get_user_by_id(user_id)


# -----------------------------
# Helpers
# -----------------------------

def current_username() -> Optional[str]:
    if current_user and getattr(current_user, "is_authenticated", False):
        return current_user.username
    return flask_session.get("username")


def current_room() -> str:
    return flask_session.get("room", DEFAULT_ROOM)


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def broadcast_online_users(room: str) -> None:
    users = sorted(room_online_users.get(room, set()))
    socketio.emit("online_users", {"room": room, "users": users}, room=room)


def normalize_room_code(room: str) -> str:
    # Normalize: keep digits only and ensure 4-digit code
    digits = ''.join(ch for ch in (room or '') if ch.isdigit())
    if not digits:
        return DEFAULT_ROOM
    # take first 4 digits; if less, left-pad with zeros
    digits = digits[:4]
    if len(digits) < 4:
        digits = digits.rjust(4, '0')
    return digits


def normalize_username(username: str) -> str:
    # Normalize usernames: lowercase, trim, replace spaces with dashes, allow alnum and dashes only
    u = (username or '').strip().lower().replace(' ', '-')
    cleaned = []
    for ch in u:
        if ch.isalnum() or ch == '-':
            cleaned.append(ch)
    u = ''.join(cleaned)
    return u[:50]


# -----------------------------
# Routes
# -----------------------------

@app.route("/")
def index():
    # Support invite links: /?room=<code>
    room_qs = request.args.get("room")
    if room_qs:
        flask_session["invite_room"] = normalize_room_code(room_qs)
    if current_user.is_authenticated:
        # If there was an invite, preselect it
        default_room = flask_session.pop("invite_room", None) or DEFAULT_ROOM
        return render_template("index.html", default_room=default_room)
    # Not authenticated: send to login; invite_room (if any) is preserved in session
    return redirect(url_for("login"))


@app.post("/join")
@login_required
def join():
    username = current_username()
    room = normalize_room_code(request.form.get("room", DEFAULT_ROOM))
    if not username:
        return redirect(url_for("login"))
    flask_session["username"] = username  # keep for socket session access
    flask_session["room"] = room
    return redirect(url_for("chat"))


@app.get("/chat")
@login_required
def chat():
    username = current_username()
    room = current_room()
    if not username:
        return redirect(url_for("login"))
    return render_template("chat.html", username=username, room=room)


@app.get("/logout")
def logout():
    logout_user()
    flask_session.clear()
    return redirect(url_for("login"))


# -----------------------------
# Auth routes
# -----------------------------

@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = normalize_username(request.form.get("username") or "")
    password = request.form.get("password") or ""
    user = get_user_by_username(username)
    if not user or not check_password_hash(user.password_hash, password):
        flash("Invalid username or password", "danger")
        return redirect(url_for("login"))
    login_user(user)
    flask_session["username"] = user.username
    # After login, if we have an invite intent, go to index with that as default
    invite_room = flask_session.pop("invite_room", None)
    if invite_room:
        flask_session["room"] = invite_room
        return redirect(url_for("chat"))
    return redirect(url_for("index"))


@app.get("/register")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("register.html")


@app.post("/register")
def register_post():
    username = normalize_username(request.form.get("username") or "")
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    email = (request.form.get("email") or "").strip() or None
    if not username or not password or password != confirm:
        flash("Please provide username and matching passwords", "danger")
        return redirect(url_for("register"))
    ok, err = create_user(username, password, email)
    if not ok:
        flash(err or "Registration failed", "danger")
        return redirect(url_for("register"))
    user = get_user_by_username(username)
    if user:
        login_user(user)
        flask_session["username"] = user.username
        invite_room = flask_session.pop("invite_room", None)
        if invite_room:
            flask_session["room"] = invite_room
            return redirect(url_for("chat"))
    flash("Registration successful. Please log in.", "success")
    return redirect(url_for("login"))


# -----------------------------
# About page
# -----------------------------

@app.get("/about")
def about():
    return render_template("about.html")

# Serve uploaded files explicitly if needed
@app.get('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# Upload endpoint (for images/audio)
# REMOVED upload endpoint

# -----------------------------
# Socket.IO events
# -----------------------------

@socketio.on("connect")
def handle_connect():
    username = current_username()
    room = current_room()
    if not username:
        # Not joined via HTTP yet; refuse until they pick a username
        return False
    username_to_sid[username] = request.sid  # type: ignore[attr-defined]
    online_users.add(username)
    last_seen_iso[username] = now_iso()
    # Send groups for this user
    user_groups = [
        {"id": gid, "name": groups[gid]["name"], "members": sorted(list(groups[gid]["members"]))}
        for gid in sorted(list(username_to_groups.get(username, set()))) if gid in groups
    ]
    emit("groups_for_user", {"groups": user_groups})


@socketio.on("join_room")
def handle_join_room(data):
    username = current_username()
    room = normalize_room_code(data.get("room") or current_room())
    if not username:
        return
    flask_session["room"] = room
    join_room(room)
    room_online_users.setdefault(room, set()).add(username)
    username_to_sid[username] = request.sid  # type: ignore[attr-defined]

    # Send last messages to the new user only, including reaction_state if available
    history = load_last_messages(room, limit=20)
    enriched = []
    for m in history:
        mid = m.get("message_id") if isinstance(m, dict) else None
        if mid is not None and int(mid) in reactions_by_message:
            per_user = reactions_by_message[int(mid)]
            counts: Dict[str, int] = {}
            by: Dict[str, List[str]] = {}
            for user, em in per_user.items():
                counts[em] = counts.get(em, 0) + 1
                by.setdefault(em, []).append(user)
            m2 = dict(m)
            m2["reaction_state"] = {"counts": counts, "by": by}
            enriched.append(m2)
        else:
            enriched.append(m)
    emit("chat_history", {"room": room, "messages": enriched})

    # Notify others in room
    emit("user_joined", {"room": room, "username": username, "timestamp_iso": now_iso()}, room=room, include_self=False)
    broadcast_online_users(room)


@socketio.on("leave_room")
def handle_leave_room(data):
    username = current_username()
    room = normalize_room_code(data.get("room") or current_room())
    if not username:
        return
    leave_room(room)
    if room in room_online_users and username in room_online_users[room]:
        room_online_users[room].remove(username)
    emit("user_left", {"room": room, "username": username, "timestamp_iso": now_iso()}, room=room)
    broadcast_online_users(room)


@socketio.on("send_message")
def handle_send_message(data):
    username = current_username()
    room = normalize_room_code(data.get("room") or current_room())
    text = (data.get("text") or "").strip()
    if not username or not text:
        return
    ts = now_iso()
    message_id = generate_message_id()
    save_message(room, username, text, ts, message_id=message_id)
    emit(
        "room_message",
        {"room": room, "username": username, "text": text, "timestamp_iso": ts, "message_id": message_id},
        room=room,
    )


# Typing indicators
@socketio.on("typing")
def handle_typing(data):
    username = current_username()
    if not username:
        return
    room = normalize_room_code(data.get("room") or current_room())
    is_typing = bool(data.get("is_typing"))
    # Broadcast to others in the room
    emit("user_typing", {"room": room, "username": username, "is_typing": is_typing, "timestamp_iso": now_iso()}, room=room, include_self=False)


# Delivery receipts
@socketio.on("message_delivered")
def handle_message_delivered(data):
    sender = (data.get("sender") or "").strip()
    message_id = data.get("message_id")
    if not sender or message_id is None:
        return
    target_sid = username_to_sid.get(sender)
    if target_sid:
        emit("message_delivered", {"message_id": message_id}, to=target_sid)


@socketio.on("message_seen")
def handle_message_seen(data):
    sender = (data.get("sender") or "").strip()
    message_id = data.get("message_id")
    if not sender or message_id is None:
        return
    target_sid = username_to_sid.get(sender)
    if target_sid:
        emit("message_seen", {"message_id": message_id}, to=target_sid)


# Reactions
@socketio.on("add_reaction")
def handle_add_reaction(data):
    username = current_username()
    if not username:
        return
    # accept room as-is to support group namespaces like group:ID
    room = (data.get("room") or current_room())
    message_id = data.get("message_id")
    emoji = (data.get("emoji") or "").strip()
    if not message_id or not emoji:
        return
    per_user = reactions_by_message.setdefault(int(message_id), {})
    # Enforce only one reaction per user per message: replace any previous
    per_user[username] = emoji
    # Build counts and by lists
    counts: Dict[str, int] = {}
    by: Dict[str, List[str]] = {}
    for user, em in per_user.items():
        counts[em] = counts.get(em, 0) + 1
        by.setdefault(em, []).append(user)
    emit("reaction_state", {"message_id": message_id, "counts": counts, "by": by}, room=room)


# Group management
@socketio.on('create_group')
def handle_create_group(data):
    creator = current_username()
    if not creator:
        return
    name = (data.get('name') or '').strip() or f"Group {now_iso()}"
    members = set([creator] + [m.strip().lower() for m in (data.get('members') or []) if m and isinstance(m, str)])
    gid = generate_group_id()
    groups[gid] = {"id": gid, "name": name, "members": members, "messages": []}
    for m in members:
        username_to_groups.setdefault(m, set()).add(gid)
        # If online, notify user and auto-join the Socket.IO room
        sid = username_to_sid.get(m)
        if sid:
            emit('group_created', {"id": gid, "name": name, "members": sorted(list(members))}, to=sid)
    # Also notify creator of refreshed list
    user_groups = [
        {"id": g, "name": groups[g]["name"], "members": sorted(list(groups[g]["members"]))}
        for g in sorted(list(username_to_groups.get(creator, set()))) if g in groups
    ]
    emit("groups_for_user", {"groups": user_groups})

@socketio.on('join_group')
def handle_join_group(data):
    username = current_username()
    gid = (data.get('group_id') or '').strip()
    if not username or gid not in groups or username not in groups[gid]['members']:
        return
    join_room(f"group:{gid}")
    # Optionally send last messages
    history = groups[gid].get('messages', [])[-50:]
    emit('group_history', {"group_id": gid, "messages": history})

@socketio.on('leave_group')
def handle_leave_group(data):
    username = current_username()
    gid = (data.get('group_id') or '').strip()
    if not username or gid not in groups:
        return
    leave_room(f"group:{gid}")

@socketio.on('group_message')
def handle_group_message(data):
    username = current_username()
    gid = (data.get('group_id') or '').strip()
    text = (data.get('text') or '').strip()
    if not username or gid not in groups or username not in groups[gid]['members'] or not text:
        return
    ts = now_iso()
    mid = generate_message_id()
    payload = {"group_id": gid, "username": username, "text": text, "timestamp_iso": ts, "message_id": mid}
    groups[gid]['messages'].append(payload)
    if len(groups[gid]['messages']) > 200:
        groups[gid]['messages'] = groups[gid]['messages'][-200:]
    emit('group_message', payload, room=f"group:{gid}")

@socketio.on('group_typing')
def handle_group_typing(data):
    username = current_username()
    gid = (data.get('group_id') or '').strip()
    is_typing = bool(data.get('is_typing'))
    if not username or gid not in groups or username not in groups[gid]['members']:
        return
    emit('group_typing', {"group_id": gid, "username": username, "is_typing": is_typing, "timestamp_iso": now_iso()}, room=f"group:{gid}", include_self=False)

@socketio.on('message_delivered_group')
def handle_group_delivered(data):
    sender = (data.get('sender') or '').strip()
    message_id = data.get('message_id')
    if not sender or message_id is None:
        return
    sid = username_to_sid.get(sender)
    if sid:
        emit('message_delivered_group', {"message_id": message_id}, to=sid)

@socketio.on('message_seen_group')
def handle_group_seen(data):
    sender = (data.get('sender') or '').strip()
    message_id = data.get('message_id')
    if not sender or message_id is None:
        return
    sid = username_to_sid.get(sender)
    if sid:
        emit('message_seen_group', {"message_id": message_id}, to=sid)


@socketio.on("disconnect")
def handle_disconnect():
    username = current_username()
    room = current_room()
    if username:
        online_users.discard(username)
        last_seen_iso[username] = now_iso()
    if username and room in room_online_users and username in room_online_users[room]:
        room_online_users[room].remove(username)
        emit("user_left", {"room": room, "username": username, "timestamp_iso": now_iso()}, room=room)
        broadcast_online_users(room)

# Profile fetch
@socketio.on('get_profile')
def handle_get_profile(data):
    requester = current_username()
    username = (data.get('username') or '').strip().lower()
    if not requester or not username:
        return
    emit('profile', {
        'username': username,
        'online': username in online_users,
        'last_seen': last_seen_iso.get(username),
        'email': get_user_email(username)
    })


def main():
    _sqlite_init()
    base_port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1")

    # Try a few consecutive ports to avoid sock.bind errors if busy
    max_tries = 10
    last_err = None
    for i in range(max_tries):
        port = base_port + i
        try:
            socketio.run(app, host=host, port=port)
            return
        except OSError as e:
            last_err = e
            continue
    # If we get here, all attempts failed
    raise SystemExit(f"Failed to bind on {host}:{base_port}-{base_port+max_tries-1}: {last_err}")


if __name__ == "__main__":
    main()


