import sqlite3

from flask import Blueprint, request

bp = Blueprint("users", __name__)
DB_PATH = "users.db"


@bp.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()
    conn.close()
    return {"users": rows}
