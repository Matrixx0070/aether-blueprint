"""Fixture 01: get_user(). Reviewer should flag CWE-89."""
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT name, email FROM users WHERE id = " + user_id)
    return cur.fetchone() or ("not found", 404)
