"""SAFE SAMPLES: secure equivalents that must NOT be flagged.

Used in the demo to prove the scanner distinguishes safe from unsafe code.
"""
import hashlib
import os
import secrets
import subprocess

import yaml
from flask import request


def safe_sql(cursor):
    # Parameterized query - safe
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def safe_command():
    # Argument list, shell=False (default) - safe
    name = request.args.get("name")
    subprocess.run(["echo", name], shell=False)


def safe_hash(data):
    # SHA-256 - acceptable
    return hashlib.sha256(data).hexdigest()


def safe_token():
    # Cryptographically secure randomness - safe
    return secrets.token_hex(16)


def safe_yaml(stream):
    # SafeLoader - safe
    return yaml.safe_load(stream)


def safe_secret():
    # Loaded from environment, not hardcoded - safe
    return os.environ.get("DB_PASSWORD")


def safe_path(base_dir):
    # Validated against a base directory - safe
    filename = request.args.get("file")
    full = os.path.realpath(os.path.join(base_dir, os.path.basename(filename)))
    if not full.startswith(os.path.realpath(base_dir)):
        raise ValueError("invalid path")
    with open(full) as fh:
        return fh.read()
