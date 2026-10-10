"""VULNERABLE SAMPLE: Weak cryptography and insecure randomness."""
import hashlib
import random


def hash_password_md5(password):
    # MD5 is broken for security use
    return hashlib.md5(password.encode()).hexdigest()


def hash_sha1(data):
    # SHA1 is deprecated for security
    return hashlib.sha1(data).hexdigest()


def make_token():
    # insecure random used for a security token
    token = random.randint(100000, 999999)
    return token
