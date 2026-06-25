"""Fixture 06: restore_session(). Reviewer should flag CWE-502."""
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route("/session", methods=["POST"])
def restore_session():
    blob = request.form["state"]
    data = pickle.loads(base64.b64decode(blob))
    return {"restored": True, "keys": list(data.keys())}
