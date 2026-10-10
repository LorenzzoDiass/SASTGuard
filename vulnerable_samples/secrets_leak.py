"""VULNERABLE SAMPLE: Hardcoded secrets."""

# Hardcoded password
DB_PASSWORD = "SuperSecretP@ssw0rd"

# Hardcoded API key (AWS-shaped) and token
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
api_token = "sk-abc123def456ghi789jkl012mno345pqr"


def connect():
    return {"user": "admin", "password": DB_PASSWORD}
