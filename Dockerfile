# Sentinel API -- minimal, offline by default (the core has zero runtime deps).
FROM python:3.11-slim

# Build with --build-arg LIVE=1 to include the Anthropic SDK for live Claude mode.
ARG LIVE=0

WORKDIR /app

# Copy only what the runtime needs (see .dockerignore for exclusions).
COPY firewall/ ./firewall/
COPY agents/ ./agents/
COPY llm.py sentinel_api.py ./

RUN if [ "$LIVE" = "1" ]; then pip install --no-cache-dir "anthropic==0.40.0"; fi

# Offline unless an API key is provided at runtime (-e ANTHROPIC_API_KEY=...).
ENV SENTINEL_FORCE_OFFLINE=1 \
    PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Container-native healthcheck against the liveness endpoint.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health')" || exit 1

# Run as non-root.
RUN useradd --create-home --uid 10001 sentinel
USER sentinel

CMD ["python", "sentinel_api.py"]
