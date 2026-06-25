"""Fixture 18: render(). Reviewer should flag CWE-79."""
from jinja2 import Environment, FileSystemLoader
from flask import Flask, request

app = Flask(__name__)
env = Environment(loader=FileSystemLoader("templates"), autoescape=False)

@app.route("/hello")
def render():
    name = request.args.get("name", "world")
    tpl = env.get_template("hello.html")
    return tpl.render(name=name)
