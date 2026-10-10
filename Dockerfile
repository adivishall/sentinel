# Sentinel -- API + console. One runtime dependency (cryptography); offline by default.
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="Financial decision security for AI-assisted finance: AI may recommend; trusted evidence, deterministic policy and authorization decide." \
      org.opencontainers.image.source="https://github.com/adivishall/sentinel" \
      org.opencontainers.image.licenses="MIT"

ARG LIVE=0
WORKDIR /app

COPY sentinel/ ./sentinel/
COPY ui/ ./ui/
COPY results/ ./results/
COPY pyproject.toml README.md ./

RUN pip install --no-cache-dir . && if [ "$LIVE" = "1" ]; then pip install --no-cache-dir "anthropic==1.11.0"; fi

ENV SENTINEL_FORCE_OFFLINE=1 \
    SENTINEL_DB=/data/sentinel.db \
    PORT=8000 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 sentinel && mkdir -p /data && chown sentinel /data
USER sentinel
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health')" || exit 1

# Binds all interfaces inside the container, so the server refuses to start unless it has
# SENTINEL_API_KEY (better: SENTINEL_API_KEY_FILE, a mounted secret) or, for a throwaway
# demo, SENTINEL_INSECURE_DEMO=1 (`make docker-run`). See docs/DEPLOYMENT.md.
CMD ["sh", "-c", "sentinel serve --host 0.0.0.0 --port ${PORT} --analyze"]
