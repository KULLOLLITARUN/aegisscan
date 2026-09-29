"""Benchmark corpus: assorted weaknesses. Intentionally vulnerable."""
import os
import tempfile
import xml.etree.ElementTree as ET

import jinja2
from flask import Flask

app = Flask(__name__)


def make_tmp():
    return tempfile.mktemp()


def open_perms(path):
    os.chmod(path, 0o777)


def parse(xml_text):
    return ET.fromstring(xml_text)


def render(template_text):
    return jinja2.Environment(autoescape=False).from_string(template_text).render()


def check_admin(user):
    assert user["admin"], "admin required"


def swallow(action):
    try:
        action()
    except Exception:
        pass


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
