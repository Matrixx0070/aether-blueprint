"""Fixture 07: fetch(). Reviewer should flag CWE-918."""
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    target = request.args.get("url")
    r = requests.get(target, timeout=5)
    return r.text
