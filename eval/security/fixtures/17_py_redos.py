"""Fixture 17: validate_email(). Reviewer should flag CWE-1333 / CWE-400."""
import re
from flask import Flask, request

app = Flask(__name__)

EMAIL_RE = re.compile(r"^([a-zA-Z0-9_.+-])+@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$")

@app.route("/check")
def validate_email():
    addr = request.args.get("email", "")
    if EMAIL_RE.match(addr):
        return "ok"
    return "bad", 400
