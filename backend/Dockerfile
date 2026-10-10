# ======================================================
# SASTGuard backend image (API + worker + CLI)
# Includes the SAST engines: native (AST+taint), Bandit and Semgrep.
# ======================================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps: build tools for psycopg2, curl for healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (better layer caching).
COPY requirements.txt requirements-postgres.txt requirements-sast.txt ./
RUN pip install -r requirements.txt \
    && pip install -r requirements-postgres.txt \
    && pip install -r requirements-sast.txt

# Copy application code.
COPY . /app

# Non-root user for safety.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/uploads \
    && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8000

# Default command runs the API; the worker service overrides this in compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
