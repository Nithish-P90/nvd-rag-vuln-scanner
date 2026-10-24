import hashlib
import json
import re
import sqlite3
import subprocess
from pathlib import Path

import yaml
from flask import Blueprint, abort, request, send_file

bp = Blueprint("safe", __name__)
BASE_DIR = Path("/srv/app/public").resolve()
HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


@bp.route("/safe/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("users.db")
    rows = conn.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()
    conn.close()
    return {"users": rows}


@bp.route("/safe/ping")
def ping():
    host = request.args.get("host", "")
    if not HOSTNAME.fullmatch(host):
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return {"output": result.stdout}


@bp.route("/safe/file")
def get_file():
    target = (BASE_DIR / request.args.get("file", "")).resolve()
    if not target.is_relative_to(BASE_DIR):
        abort(404)
    return send_file(target)


@bp.route("/safe/config", methods=["POST"])
def load_config():
    data = yaml.safe_load(request.data) or {}
    meta = json.loads(request.form.get("meta", "{}"))
    return {"keys": sorted(data), "meta": meta}


def checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
