"""VULNERABLE SAMPLE: Command Injection and dangerous process calls."""
import os
import subprocess

from flask import request


def ping_host():
    # SOURCE -> SINK: untrusted host reaches os.system
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # command injection


def run_cmd(cmd):
    # subprocess with shell=True is dangerous
    subprocess.run(cmd, shell=True)
