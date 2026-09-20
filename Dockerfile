# SOAR Intelligence API (FastAPI). Non-root, models trained at build time, health-checked.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin soar

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY alembic.ini pyproject.toml ./
COPY migrations ./migrations
COPY ai ./ai
COPY soar ./soar
RUN mkdir -p /app/data /app/models && chown -R soar:soar /app

USER soar
ENV SOAR_DATA_DIR=/app/data SOAR_MODEL_DIR=/app/models

# Train the bundled models once, at build time (seeded, so the result is reproducible). Metrics are
# printed into the build log and stored in /app/models/*/metadata.json.
RUN SOAR_ENV=testing python -m soar.cli train-models | tail -n 40

ENV SOAR_ENV=production
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

# One worker: the login rate limiter is per-process (see docs/DEPLOYMENT.md).
CMD ["uvicorn", "soar.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
