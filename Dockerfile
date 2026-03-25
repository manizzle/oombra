FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps (cache layer — only rebuilds when pyproject.toml changes)
COPY pyproject.toml .
COPY nur/ nur/
RUN pip install --no-cache-dir ".[server,server-pg]" boto3

# Demo data + pre-scraped feeds
COPY demo/ demo/
COPY data/ data/

# Non-root user
RUN useradd -m nur && chown -R nur:nur /app
USER nur

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "nur.server.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
