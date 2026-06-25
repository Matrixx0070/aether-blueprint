"""Fixture 04: ping(). Reviewer should flag CWE-78."""
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return out.decode()
