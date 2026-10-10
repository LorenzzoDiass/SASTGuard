"""VULNERABLE SAMPLE: insecure network config and Flask debug."""
import requests
from flask import Flask

app = Flask(__name__)


def fetch(url):
    # TLS verification disabled -> MITM
    return requests.get(url, verify=False)


if __name__ == "__main__":
    # debug=True exposes the Werkzeug console in production
    app.run(host="0.0.0.0", debug=True)
