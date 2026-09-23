# Sentinel -- API + console. Standard library only; offline by default.
FROM python:3.11-slim

ARG LIVE=0
WORKDIR /app

COPY sentinel/ ./sentinel/
COPY ui/ ./ui/
COPY results/ ./results/
COPY pyproject.toml README.md ./

RUN pip install --no-cache-dir . && if [ "$LIVE" = "1" ]; then pip install --no-cache-dir "anthropic==0.40.0"; fi

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

CMD ["sh", "-c", "sentinel serve --host 0.0.0.0 --port ${PORT} --analyze"]
