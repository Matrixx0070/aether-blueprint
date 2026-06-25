"""Fixture 02: download(). Reviewer should flag CWE-22."""
import os
from flask import Flask, request, send_file

app = Flask(__name__)
UPLOAD_DIR = "/var/uploads"

@app.route("/download")
def download():
    filename = request.args.get("name")
    path = os.path.join(UPLOAD_DIR, filename)
    return send_file(path)
