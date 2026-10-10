"""VULNERABLE SAMPLE: Path Traversal."""
from flask import request


def read_file():
    # SOURCE: untrusted filename
    filename = request.args.get("file")
    # SINK: opened directly without validation -> path traversal
    with open(filename) as fh:
        return fh.read()
