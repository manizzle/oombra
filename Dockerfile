FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cache layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[server]"

# Copy source
COPY vigil/ vigil/
COPY demo/ demo/

# Non-root user
RUN useradd -m vigil && chown -R vigil:vigil /app
USER vigil

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default: start server with auto-ingest
CMD ["python", "-m", "uvicorn", "vigil.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
