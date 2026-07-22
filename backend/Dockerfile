# MCPGuard backend image.
# Security: runs as a non-root user, no build tools in the final layer.
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code.
COPY app ./app
COPY seeds ./seeds
COPY pytest.ini .

# Create and drop to a non-root user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Healthcheck hits the public health endpoint. Reads PORT from the environment
# so it tracks whatever port the app binds to (PaaS hosts inject their own).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health').status==200 else 1)"

# Bind to $PORT when the host provides one (Render, Railway, Fly, …), falling
# back to 8000 for local docker-compose. Shell form so the variable is expanded
# at runtime rather than baked in at build time.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
