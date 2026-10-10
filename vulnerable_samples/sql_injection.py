"""VULNERABLE SAMPLE: SQL Injection.

Demonstrates tainted user input flowing into a SQL query via string
concatenation. SASTGuard should detect this via taint analysis
(SOURCE -> PROPAGATION -> SINK) and the AST SQL rule.

This file is for scanning only. It is never executed by the platform.
"""
import sqlite3

from flask import request


def get_user(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # SOURCE: untrusted input
    user_id = request.args.get("id")

    # PROPAGATION: tainted value concatenated into the query
    query = "SELECT * FROM users WHERE id = " + user_id

    # SINK: query execution -> SQL Injection
    cursor.execute(query)
    return cursor.fetchall()
