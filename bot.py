import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib import error as urlerror
from urllib import request as urlrequest

import psutil
from flask import Flask, Response, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_ROOT = os.path.join(BASE_DIR, "USERS")
DATA_DIR = os.path.join(BASE_DIR, "DATA")
USERS_DB = os.path.join(DATA_DIR, "users.json")

os.makedirs(USERS_ROOT, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET_KEY", "CHANGE_ME_" + os.urandom(16).hex())

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "hama")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "1211")
PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")
PORT_START = int(os.environ.get("PANEL_PORT_START", "9000"))
CPU_LIMIT_PERCENT = float(os.environ.get("SERVER_CPU_LIMIT_PERCENT", "130"))
MEMORY_LIMIT_MB = float(os.environ.get("SERVER_MEMORY_LIMIT_MB", "512"))

running_procs = {}
server_states = {}
monitor_flags = {}
lock = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc)


def dt_to_iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def iso_to_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def get_base_url():
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    try:
        return request.host_url.rstrip("/")
    except Exception:
        return ""


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def sanitize_folder_name(name):
    name = (name or "").strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "", name)
    return name[:120]


def safe_name(name):
    name = (name or "").strip()
    name = re.sub(r"[\\/]+", "", name)
    name = re.sub(r"[^A-Za-z0-9\-_\. ]", "", name)
    return name[:200].strip()


def public_code_from_port(port):
    return f"p{int(port)}"


def canonical_key(owner, folder):
    return f"{owner}::{folder}"


def set_state(key, state):
    with lock:
        server_states[key] = state


def get_state(key):
    with lock:
        return server_states.get(key, "Offline")


def get_user_servers_root(username):
    return os.path.join(USERS_ROOT, username, "servers")


def get_server_dir(owner, folder):
    return os.path.join(get_user_servers_root(owner), folder)


def ensure_user_dirs(username):
    os.makedirs(get_user_servers_root(username), exist_ok=True)


def parse_server_key(key, allow_admin):
    key = (key or "").strip()
    if "::" in key:
        owner, folder = key.split("::", 1)
        if not allow_admin or not is_admin_session():
            raise ValueError("forbidden")
        return owner.strip(), folder.strip()
    return current_username(), key


def runtime_key_from_request(key):
    owner, folder = parse_server_key(key, allow_admin=True)
    return canonical_key(owner, folder), owner, folder


def can_access_key(key):
    try:
        owner, _folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return False
    return is_admin_session() or owner == current_username()


def safe_join_server_path(key, rel_path=""):
    _rt, owner, folder = runtime_key_from_request(key)
    root = os.path.abspath(get_server_dir(owner, folder))
    rel_path = (rel_path or "").replace("\\", "/").strip()
    if rel_path.startswith("/") or rel_path.startswith("~"):
        rel_path = rel_path.lstrip("/").lstrip("~")
    joined = os.path.abspath(os.path.join(root, rel_path))
    if not (joined == root or joined.startswith(root + os.sep)):
        raise ValueError("Invalid path")
    return joined


def log_append(key, text):
    try:
        if "::" in key:
            owner, folder = key.split("::", 1)
        else:
            owner, folder = parse_server_key(key, allow_admin=True)
        server_dir = get_server_dir(owner, folder)
        os.makedirs(server_dir, exist_ok=True)
        path = os.path.join(server_dir, "server.log")
        with open(path, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text)
    except Exception:
        pass


def load_users():
    if not os.path.exists(USERS_DB):
        return {"users": []}
    try:
        with open(USERS_DB, "r", encoding="utf-8") as f:
            data = json.load(f) or {"users": []}
        if "users" not in data:
            data = {"users": []}
        return data
    except Exception:
        return {"users": []}


def save_users(db):
    tmp = USERS_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_DB)


def find_user(db, username):
    u = (username or "").strip().lower()
    for x in db.get("users", []):
        if (x.get("username") or "").strip().lower() == u:
            return x
    return None


def is_admin_session():
    u = session.get("user") or {}
    return bool(u.get("is_admin"))


def current_username():
    u = session.get("user") or {}
    return (u.get("username") or "").strip()


def user_is_expired(user):
    expires_at = iso_to_dt(user.get("expires_at"))
    return bool(expires_at and utc_now() > expires_at)


def get_public_url(code):
    base = get_base_url()
    if not base:
        return f"/proxy/{code}/"
    return f"{base}/proxy/{code}/"


def allocate_port(db):
    used = set()
    for u in db.get("users", []):
        p = u.get("server_port")
        if isinstance(p, int):
            used.add(p)
    port = PORT_START
    while port in used:
        port += 1
    return port


def ensure_meta(owner, folder):
    server_dir = get_server_dir(owner, folder)
    os.makedirs(server_dir, exist_ok=True)
    meta_path = os.path.join(server_dir, "meta.json")
    defaults = {
        "display_name": folder,
        "startup_file": "",
        "owner": owner,
        "banned": False,
        "port": None,
        "public_code": "",
        "storage_limit_mb": STORAGE_LIMIT_MB,
        "memory_limit_mb": MEMORY_LIMIT_MB,
        "cpu_limit_percent": CPU_LIMIT_PERCENT,
    }
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            data = {}
    else:
        data = {}
    changed = False
    for k, v in defaults.items():
        if k not in data:
            data[k] = v
            changed = True
    if data.get("owner") != owner:
        data["owner"] = owner
        changed = True
    if not data.get("public_code") and data.get("port"):
        data["public_code"] = public_code_from_port(data.get("port"))
        changed = True
    if changed or not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    return meta_path


def read_meta(owner, folder):
    meta_path = ensure_meta(owner, folder)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except Exception:
        data = {}
    if not data.get("public_code") and data.get("port"):
        data["public_code"] = public_code_from_port(data.get("port"))
    return data


def write_meta(owner, folder, meta):
    if not meta.get("public_code") and meta.get("port"):
        meta["public_code"] = public_code_from_port(meta.get("port"))
    meta_path = ensure_meta(owner, folder)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def get_server_size_bytes(server_dir):
    total = 0
    for root, _dirs, files in os.walk(server_dir):
        for file in files:
            full = os.path.join(root, file)
            try:
                total += os.path.getsize(full)
            except OSError:
                pass
    return total


def get_server_size_mb(server_dir):
    return get_server_size_bytes(server_dir) / 1024 / 1024


def stop_proc(runtime_key):
    proc_tuple = running_procs.pop(runtime_key, None)
    monitor_flags.pop(runtime_key, None)
    if not proc_tuple:
        return
    proc, logf = proc_tuple
    try:
        p = psutil.Process(proc.pid)
        for child in p.children(recursive=True):
            try:
                child.kill()
            except Exception:
                pass
        p.kill()
    except Exception:
        pass
    try:
        logf.close()
    except Exception:
        pass


def stop_all_servers_for_user(username):
    prefix = username + "::"
    for key in list(running_procs.keys()):
        if key.startswith(prefix):
            stop_proc(key)
            set_state(key, "Offline")


def ensure_requirements_installed(owner, folder):
    server_dir = get_server_dir(owner, folder)
    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.exists(req_path):
        raise FileNotFoundError("requirements.txt is required before starting this server.")
    log_append(canonical_key(owner, folder), "[SYSTEM] Installing requirements.txt...\n")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=server_dir)
    log_append(canonical_key(owner, folder), "[SYSTEM] requirements installed ✅\n")


def start_server_process(owner, folder, startup_file, port):
    server_dir = get_server_dir(owner, folder)
    log_path = os.path.join(server_dir, "server.log")
    log_file = open(log_path, "a", encoding="utf-8", errors="ignore")
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["PANEL_PUBLIC_BASE"] = get_base_url()
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-u", startup_file],
        cwd=server_dir,
        stdout=log_file,
        stderr=log_file,
        env=env,
    )
    return proc, log_file


def monitor_process_loop(runtime_key, owner, folder):
    server_dir = get_server_dir(owner, folder)
    monitor_flags[runtime_key] = True
    while monitor_flags.get(runtime_key):
        proc_tuple = running_procs.get(runtime_key)
        if not proc_tuple:
            break
        proc, _ = proc_tuple
        if proc.poll() is not None:
            set_state(runtime_key, "Offline")
            break
        try:
            p = psutil.Process(proc.pid)
            cpu = p.cpu_percent(interval=0.35)
            mem_mb = p.memory_info().rss / 1024 / 1024
            storage_mb = get_server_size_mb(server_dir)
            if storage_mb > STORAGE_LIMIT_MB:
                log_append(runtime_key, f"[LIMIT] Storage exceeded: {storage_mb:.1f} MB / {STORAGE_LIMIT_MB:.0f} MB\n")
                stop_proc(runtime_key)
                set_state(runtime_key, "Storage Limit")
                break
            if mem_mb > MEMORY_LIMIT_MB:
                log_append(runtime_key, f"[LIMIT] Memory exceeded: {mem_mb:.1f} MB / {MEMORY_LIMIT_MB:.0f} MB\n")
                stop_proc(runtime_key)
                set_state(runtime_key, "Memory Limit")
                break
            if cpu > CPU_LIMIT_PERCENT:
                log_append(runtime_key, f"[LIMIT] CPU exceeded: {cpu:.1f}% / {CPU_LIMIT_PERCENT:.0f}%\n")
                stop_proc(runtime_key)
                set_state(runtime_key, "CPU Limit")
                break
        except Exception:
            pass
        time.sleep(2.0)
    monitor_flags.pop(runtime_key, None)


def background_start(runtime_key, owner, folder, startup_file):
    try:
        set_state(runtime_key, "Installing")
        log_append(runtime_key, "[SYSTEM] Preparing server...\n")
        ensure_requirements_installed(owner, folder)
        meta = read_meta(owner, folder)
        port = int(meta.get("port") or 0)
        code = meta.get("public_code") or public_code_from_port(port)
        if not port:
            raise RuntimeError("Server port is missing")
        set_state(runtime_key, "Starting")
        log_append(runtime_key, f"[SYSTEM] Starting main file: {startup_file}\n")
        log_append(runtime_key, f"[SYSTEM] Public URL: /proxy/{code}/\n")
        proc, logf = start_server_process(owner, folder, startup_file, port)
        running_procs[runtime_key] = (proc, logf)
        time.sleep(2.2)
        if proc.poll() is None:
            set_state(runtime_key, "Running")
            threading.Thread(target=monitor_process_loop, args=(runtime_key, owner, folder), daemon=True).start()
        else:
            set_state(runtime_key, "Offline")
    except FileNotFoundError as e:
        log_append(runtime_key, f"[SYSTEM] {e}\n")
        set_state(runtime_key, "Offline")
    except subprocess.CalledProcessError as e:
        log_append(runtime_key, f"[SYSTEM] requirements install failed: {e}\n")
        set_state(runtime_key, "Offline")
    except Exception as e:
        log_append(runtime_key, f"[SYSTEM] Start failed: {e}\n")
        set_state(runtime_key, "Offline")


def list_servers_for_user(username):
    ensure_user_dirs(username)
    root = get_user_servers_root(username)
    items = []
    for folder in sorted(os.listdir(root)):
        server_dir = get_server_dir(username, folder)
        if not os.path.isdir(server_dir):
            continue
        meta = read_meta(username, folder)
        runtime_key = canonical_key(username, folder)
        code = meta.get("public_code") or public_code_from_port(meta.get("port") or PORT_START)
        storage_mb = get_server_size_mb(server_dir)
        items.append({
            "title": meta.get("display_name", folder),
            "folder": folder,
            "owner": username,
            "key": folder,
            "runtime_key": runtime_key,
            "startup_file": meta.get("startup_file", ""),
            "status": "Banned" if meta.get("banned") else get_state(runtime_key),
            "public_code": code,
            "url": get_public_url(code),
            "port": meta.get("port"),
            "storage_mb": round(storage_mb, 2),
            "storage_limit_mb": meta.get("storage_limit_mb", STORAGE_LIMIT_MB),
            "memory_limit_mb": meta.get("memory_limit_mb", MEMORY_LIMIT_MB),
            "cpu_limit_percent": meta.get("cpu_limit_percent", CPU_LIMIT_PERCENT),
        })
    return items


def list_all_servers_for_admin():
    servers = []
    if not os.path.isdir(USERS_ROOT):
        return servers
    for owner in sorted(os.listdir(USERS_ROOT)):
        root = get_user_servers_root(owner)
        if not os.path.isdir(root):
            continue
        for item in list_servers_for_user(owner):
            item["key"] = canonical_key(owner, item["folder"])
            servers.append(item)
    return servers


def get_session_user_record():
    if is_admin_session():
        return None
    db = load_users()
    return find_user(db, current_username())


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        if not is_admin_session():
            user = get_session_user_record()
            if not user:
                session.pop("user", None)
                return redirect("/login")
            if not user.get("active", True) or user_is_expired(user):
                session.pop("user", None)
                return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        if not is_admin_session():
            return jsonify({"success": False, "message": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


def create_user_and_server(username, password, days, server_name):
    db = load_users()
    if find_user(db, username):
        return False, "Username already exists"
    if not username or not re.fullmatch(r"[A-Za-z0-9_\.]+", username) or len(username) < 3:
        return False, "Username allowed: letters, numbers, _ and ."
    if len(password) < 6:
        return False, "Password must be at least 6 chars"
    if username.upper() == ADMIN_USERNAME.upper():
        return False, "This username is reserved"
    if days < 1:
        return False, "Days must be at least 1"

    server_folder = sanitize_folder_name(username)
    server_name = (server_name or username).strip()[:80] or username
    port = allocate_port(db)
    public_code = public_code_from_port(port)
    expires_at = utc_now() + timedelta(days=days)

    db["users"].append({
        "username": username,
        "password_hash": generate_password_hash(password),
        "active": True,
        "created_at": dt_to_iso(utc_now()),
        "expires_at": dt_to_iso(expires_at),
        "server_folder": server_folder,
        "server_name": server_name,
        "server_port": port,
        "public_code": public_code,
        "days_total": days,
    })
    save_users(db)

    ensure_user_dirs(username)
    server_dir = get_server_dir(username, server_folder)
    os.makedirs(server_dir, exist_ok=True)
    open(os.path.join(server_dir, "server.log"), "a", encoding="utf-8").close()
    write_meta(username, server_folder, {
        "display_name": server_name,
        "startup_file": "",
        "owner": username,
        "banned": False,
        "port": port,
        "public_code": public_code,
        "storage_limit_mb": STORAGE_LIMIT_MB,
        "memory_limit_mb": MEMORY_LIMIT_MB,
        "cpu_limit_percent": CPU_LIMIT_PERCENT,
    })
    set_state(canonical_key(username, server_folder), "Offline")
    return True, "Created"


@app.route("/")
@login_required
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/create")
def create_page():
    return redirect("/login")


@app.route("/admin")
@login_required
def admin_page():
    if not is_admin_session():
        return redirect("/")
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["user"] = {"username": ADMIN_USERNAME, "is_admin": True}
        return jsonify({"success": True, "is_admin": True})

    db = load_users()
    user = find_user(db, username)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    if not user.get("active", True):
        return jsonify({"success": False, "message": "Account is inactive"}), 403
    if user_is_expired(user):
        return jsonify({"success": False, "message": "Account expired. Contact the admin."}), 403

    session["user"] = {"username": user.get("username"), "is_admin": False}
    ensure_user_dirs(user.get("username"))
    return jsonify({"success": True, "is_admin": False})


@app.route("/api/auth/create", methods=["POST"])
def api_create():
    return jsonify({"success": False, "message": "Public account creation is disabled."}), 403


@app.route("/servers")
@login_required
def servers():
    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(current_username())})


@app.route("/server/stats/<path:key>")
@login_required
def server_stats(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    runtime_key, owner, folder = runtime_key_from_request(key)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"status": "Offline", "cpu": "0%", "mem": "0 MB", "logs": "", "ip": get_ip()}), 404

    meta = read_meta(owner, folder)
    state = get_state(runtime_key)
    proc_tuple = running_procs.get(runtime_key)
    running = False
    cpu = "0%"
    mem = "0 MB"

    storage_mb = get_server_size_mb(server_dir)
    if proc_tuple:
        proc, _ = proc_tuple
        if psutil.pid_exists(proc.pid):
            try:
                p = psutil.Process(proc.pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    running = True
                    cpu_val = p.cpu_percent(interval=0.10)
                    mem_val = p.memory_info().rss / 1024 / 1024
                    cpu = f"{cpu_val:.1f}%"
                    mem = f"{mem_val:.1f} MB"
                    if storage_mb > STORAGE_LIMIT_MB:
                        log_append(runtime_key, f"[LIMIT] Storage exceeded: {storage_mb:.1f} MB / {STORAGE_LIMIT_MB:.0f} MB\n")
                        stop_proc(runtime_key)
                        state = "Storage Limit"
                        set_state(runtime_key, state)
                        running = False
                    elif mem_val > MEMORY_LIMIT_MB:
                        log_append(runtime_key, f"[LIMIT] Memory exceeded: {mem_val:.1f} MB / {MEMORY_LIMIT_MB:.0f} MB\n")
                        stop_proc(runtime_key)
                        state = "Memory Limit"
                        set_state(runtime_key, state)
                        running = False
                    elif cpu_val > CPU_LIMIT_PERCENT:
                        log_append(runtime_key, f"[LIMIT] CPU exceeded: {cpu_val:.1f}% / {CPU_LIMIT_PERCENT:.0f}%\n")
                        stop_proc(runtime_key)
                        state = "CPU Limit"
                        set_state(runtime_key, state)
                        running = False
            except Exception:
                pass

    try:
        with open(os.path.join(server_dir, "server.log"), "r", encoding="utf-8", errors="ignore") as f:
            logs = f.read()
    except Exception:
        logs = ""

    code = meta.get("public_code") or public_code_from_port(meta.get("port") or PORT_START)
    if meta.get("banned", False):
        state = "Banned"
    elif running and state not in ("CPU Limit", "Memory Limit", "Storage Limit"):
        state = "Running"
        set_state(runtime_key, state)
    elif state not in ("Installing", "Starting", "CPU Limit", "Memory Limit", "Storage Limit"):
        state = "Offline"
        set_state(runtime_key, state)

    return jsonify({
        "status": state,
        "cpu": cpu,
        "mem": mem,
        "logs": logs,
        "ip": get_ip(),
        "storage_mb": round(storage_mb, 2),
        "storage_limit_mb": STORAGE_LIMIT_MB,
        "memory_limit_mb": MEMORY_LIMIT_MB,
        "public_code": code,
        "url": get_public_url(code),
        "port": meta.get("port") or "",
        "cpu_limit_percent": CPU_LIMIT_PERCENT,
    })


@app.route("/server/action/<path:key>/<act>", methods=["POST"])
@login_required
def server_action(key, act):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    runtime_key, owner, folder = runtime_key_from_request(key)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(runtime_key, "Banned")
        return jsonify({"success": False, "message": "Server is banned by admin"}), 403

    db = load_users()
    user = find_user(db, owner)
    if user and user_is_expired(user):
        stop_proc(runtime_key)
        return jsonify({"success": False, "message": "Account expired. Contact the admin."}), 403

    if act in ("stop", "restart"):
        stop_proc(runtime_key)
        set_state(runtime_key, "Offline")

    if act == "stop":
        return jsonify({"success": True})

    startup = (meta.get("startup_file") or "").strip()
    if not startup:
        return jsonify({"success": False, "message": "No main file set"}), 400

    startup_path = os.path.join(server_dir, startup)
    if not os.path.isfile(startup_path):
        return jsonify({"success": False, "message": "Main file not found"}), 404

    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.isfile(req_path):
        return jsonify({"success": False, "message": "requirements.txt is required before starting this server."}), 400

    size_mb = get_server_size_mb(server_dir)
    if size_mb > STORAGE_LIMIT_MB:
        set_state(runtime_key, "Storage Limit")
        return jsonify({"success": False, "message": f"Storage limit exceeded ({STORAGE_LIMIT_MB:.0f} MB)."}), 400

    open(os.path.join(server_dir, "server.log"), "w", encoding="utf-8").close()
    threading.Thread(target=background_start, args=(runtime_key, owner, folder, startup), daemon=True).start()
    code = meta.get("public_code") or public_code_from_port(meta.get("port") or PORT_START)
    return jsonify({"success": True, "url": get_public_url(code), "port": meta.get("port"), "public_code": code})


@app.route("/server/set-startup/<path:key>", methods=["POST"])
@login_required
def set_startup(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    _runtime_key, owner, folder = runtime_key_from_request(key)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404
    data = request.get_json(silent=True) or {}
    f = (data.get("file") or "").strip()
    if f and not os.path.isfile(os.path.join(server_dir, f)):
        return jsonify({"success": False, "message": "File not found"}), 404
    meta = read_meta(owner, folder)
    meta["startup_file"] = f
    write_meta(owner, folder, meta)
    return jsonify({"success": True})


@app.route("/files/list/<path:key>")
@login_required
def files_list(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden", "path": ""}), 403
    rel = request.args.get("path", "") or ""
    try:
        base = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path", "path": ""}), 400
    dirs, files = [], []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base), key=lambda x: (not os.path.isdir(os.path.join(base, x)), x.lower())):
            if rel == "" and name in ("meta.json", "server.log"):
                continue
            full = os.path.join(base, name)
            if os.path.isdir(full):
                dirs.append({"name": name})
            elif os.path.isfile(full):
                try:
                    size = f"{os.path.getsize(full) / 1024:.1f} KB"
                except Exception:
                    size = ""
                files.append({"name": name, "size": size})
    return jsonify({"success": True, "path": rel, "dirs": dirs, "files": files})


@app.route("/files/content/<path:key>")
@login_required
def file_content(key):
    if not can_access_key(key):
        return jsonify({"content": ""}), 403
    file_rel = request.args.get("file", "") or ""
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"content": ""}), 400
    if os.path.isdir(full):
        return jsonify({"content": ""}), 400
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": ""})


@app.route("/files/save/<path:key>", methods=["POST"])
@login_required
def file_save(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    file_rel = data.get("file", "") or ""
    content = data.get("content", "")
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400
    os.makedirs(os.path.dirname(full), exist_ok=True)
    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        _runtime_key, owner, folder = runtime_key_from_request(key)
        server_dir = get_server_dir(owner, folder)
        size_mb = get_server_size_mb(server_dir)
        if size_mb > STORAGE_LIMIT_MB:
            stop_proc(canonical_key(owner, folder))
            return jsonify({"success": False, "message": f"Storage limit exceeded ({size_mb:.1f} MB / {STORAGE_LIMIT_MB:.0f} MB)."}), 507
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/mkdir/<path:key>", methods=["POST"])
@login_required
def file_mkdir(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        os.makedirs(target, exist_ok=False)
        return jsonify({"success": True})
    except FileExistsError:
        return jsonify({"success": False, "message": "Already exists"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/rename/<path:key>", methods=["POST"])
@login_required
def file_rename(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    old = safe_name(data.get("old", ""))
    new = safe_name(data.get("new", ""))
    if not old or not new:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        src = safe_join_server_path(key, os.path.join(rel, old))
        dst = safe_join_server_path(key, os.path.join(rel, new))
        os.rename(src, dst)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/delete/<path:key>", methods=["POST"])
@login_required
def file_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    kind = (data.get("kind") or "file").strip().lower()
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        if kind == "dir":
            shutil.rmtree(target)
        else:
            os.remove(target)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/upload/<path:key>", methods=["POST"])
@login_required
def file_upload(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    rel = request.args.get("path", "") or ""
    try:
        base_dir = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400
    os.makedirs(base_dir, exist_ok=True)
    files = request.files.getlist("files") or []
    if not files:
        one = request.files.get("file")
        if one:
            files = [one]
    if not files:
        return jsonify({"success": False, "message": "No file"}), 400
    relpaths = request.form.getlist("relpaths")
    saved = 0
    for i, f in enumerate(files):
        if not f or not f.filename:
            continue
        filename = os.path.basename(f.filename)
        rp = ""
        if relpaths and i < len(relpaths):
            rp = (relpaths[i] or "").replace("\\", "/").lstrip("/")
        try:
            target_dir = safe_join_server_path(key, os.path.join(rel, os.path.dirname(rp))) if rp else base_dir
        except Exception:
            continue
        os.makedirs(target_dir, exist_ok=True)
        f.save(os.path.join(target_dir, filename))
        saved += 1
    _runtime_key, owner, folder = runtime_key_from_request(key)
    server_dir = get_server_dir(owner, folder)
    size_mb = get_server_size_mb(server_dir)
    if size_mb > STORAGE_LIMIT_MB:
        stop_proc(canonical_key(owner, folder))
        return jsonify({"success": False, "saved": saved, "message": f"Storage limit exceeded ({size_mb:.1f} MB / {STORAGE_LIMIT_MB:.0f} MB)."}), 507
    return jsonify({"success": True, "saved": saved})


@app.route("/api/admin/quickstats")
@admin_required
def admin_quickstats():
    db = load_users()
    users = db.get("users", [])
    total_servers = 0
    running = 0
    banned = 0
    memory_limited = 0
    cpu_limited = 0
    storage_limited = 0
    for s in list_all_servers_for_admin():
        total_servers += 1
        status = (s.get("status") or "").lower()
        if status == "running":
            running += 1
        if status == "banned":
            banned += 1
        if status == "memory limit":
            memory_limited += 1
        if status == "cpu limit":
            cpu_limited += 1
        if status == "storage limit":
            storage_limited += 1
    return jsonify({"success": True, "stats": {
        "servers_total": total_servers,
        "servers_running": running,
        "servers_banned": banned,
        "servers_memory_limited": memory_limited,
        "servers_cpu_limited": cpu_limited,
        "servers_storage_limited": storage_limited,
        "users_total": len(users),
        "users_active": sum(1 for u in users if u.get("active", True) and not user_is_expired(u)),
        "users_expired": sum(1 for u in users if user_is_expired(u)),
    }})


@app.route("/api/admin/servers")
@admin_required
def admin_servers():
    return jsonify({"success": True, "servers": list_all_servers_for_admin()})


@app.route("/api/admin/users")
@admin_required
def admin_users():
    db = load_users()
    users = []
    for u in db.get("users", []):
        server_folder = u.get("server_folder") or sanitize_folder_name(u.get("username") or "")
        server_dir = get_server_dir(u.get("username"), server_folder)
        size_mb = get_server_size_mb(server_dir) if os.path.isdir(server_dir) else 0.0
        expires_at = iso_to_dt(u.get("expires_at"))
        days_left = None
        if expires_at:
            days_left = max(0, int((expires_at - utc_now()).total_seconds() // 86400))
        users.append({
            "username": u.get("username"),
            "active": bool(u.get("active", True)),
            "expired": user_is_expired(u),
            "expires_at": u.get("expires_at"),
            "days_left": days_left,
            "server_name": u.get("server_name") or server_folder,
            "server_folder": server_folder,
            "server_port": u.get("server_port") or "",
            "public_code": u.get("public_code") or public_code_from_port(u.get("server_port") or PORT_START),
            "storage_mb": round(size_mb, 2),
        })
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/user/create", methods=["POST"])
@admin_required
def admin_user_create():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    days = int(data.get("days") or 0)
    server_name = (data.get("server_name") or username).strip()
    ok, message = create_user_and_server(username, password, days, server_name)
    code = 200 if ok else 400
    return jsonify({"success": ok, "message": message}), code


@app.route("/api/admin/user/update", methods=["POST"])
@admin_required
def admin_user_update():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    db = load_users()
    user = find_user(db, username)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    if "active" in data:
        user["active"] = bool(data.get("active"))
        if not user["active"]:
            stop_all_servers_for_user(username)

    if "add_days" in data:
        add_days = int(data.get("add_days") or 0)
        base = iso_to_dt(user.get("expires_at")) or utc_now()
        if base < utc_now():
            base = utc_now()
        user["expires_at"] = dt_to_iso(base + timedelta(days=add_days))

    save_users(db)
    return jsonify({"success": True})


@app.route("/api/admin/server/ban", methods=["POST"])
@admin_required
def admin_server_ban():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    banned = bool(data.get("banned", True))
    if not key or "::" not in key:
        return jsonify({"success": False, "message": "Invalid server key"}), 400
    owner, folder = key.split("::", 1)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404
    meta = read_meta(owner, folder)
    meta["banned"] = banned
    write_meta(owner, folder, meta)
    runtime_key = canonical_key(owner, folder)
    if banned:
        stop_proc(runtime_key)
        set_state(runtime_key, "Banned")
        log_append(runtime_key, "[ADMIN] Server banned.\n")
    else:
        set_state(runtime_key, "Offline")
        log_append(runtime_key, "[ADMIN] Server unbanned.\n")
    return jsonify({"success": True})


@app.route("/proxy/<code>/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/proxy/<code>/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def proxy_to_server(code, subpath):
    db = load_users()
    target_user = None
    for user in db.get("users", []):
        meta_code = user.get("public_code") or public_code_from_port(user.get("server_port") or PORT_START)
        if meta_code == code:
            target_user = user
            break
    if not target_user:
        return Response("Server code not found.", status=404)
    if not target_user.get("active", True) or user_is_expired(target_user):
        return Response("Server owner is inactive or expired.", status=403)

    owner = target_user.get("username")
    folder = target_user.get("server_folder") or sanitize_folder_name(owner)
    runtime_key = canonical_key(owner, folder)
    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        return Response("Server is banned.", status=403)

    port = int(meta.get("port") or 0)
    if not port:
        return Response("Server port is missing.", status=500)
    proc_tuple = running_procs.get(runtime_key)
    if not proc_tuple or proc_tuple[0].poll() is not None:
        return Response("Server is offline.", status=503)

    target = f"http://127.0.0.1:{port}/{subpath}"
    if request.query_string:
        target += "?" + request.query_string.decode("utf-8", errors="ignore")

    body = request.get_data()
    headers = {}
    for k, v in request.headers.items():
        if k.lower() in {"host", "content-length", "connection"}:
            continue
        headers[k] = v
    headers["X-Forwarded-For"] = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    headers["X-Forwarded-Proto"] = request.scheme
    headers["X-Forwarded-Prefix"] = f"/proxy/{code}"

    req = urlrequest.Request(target, data=body if request.method not in ("GET", "HEAD") else None, headers=headers, method=request.method)
    try:
        with urlrequest.urlopen(req, timeout=60) as resp:
            content = resp.read()
            response_headers = []
            for k, v in resp.getheaders():
                if k.lower() in {"transfer-encoding", "connection", "content-encoding", "content-length"}:
                    continue
                response_headers.append((k, v))
            return Response(content, status=resp.status, headers=response_headers)
    except urlerror.HTTPError as e:
        return Response(e.read(), status=e.code, content_type=e.headers.get_content_type())
    except Exception as e:
        return Response(
            f"Proxy error: {e}\n\nMake sure your app runs on host 0.0.0.0 and port int(os.getenv('PORT', '8000')).",
            status=502,
            content_type="text/plain; charset=utf-8",
        )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "7860")), debug=False)
