from flask import request
import sqlite3

@app.route("/u")
def get_user():
    name = request.args.get("name")
    if not name:
        return "missing"
    q = "SELECT * FROM u WHERE n='" + name + "'"
    return run(q)

def run(q):
    cur = sqlite3.connect("db").cursor()
    cur.execute(q)
    return cur.fetchall()
