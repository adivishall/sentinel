"""Structured logging for the firewall. JSON lines to stderr so a decision can be
traced end-to-end and shipped to a log aggregator unchanged. Off by default
(WARNING); set SENTINEL_LOG=INFO/DEBUG to see per-layer events."""

from __future__ import annotations

import json
import logging
import os
import sys


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"level": record.levelname, "layer": record.name, "msg": record.getMessage()}
        if hasattr(record, "detail"):
            payload["detail"] = record.detail  # type: ignore[attr-defined]
        return json.dumps(payload, default=str)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(_JsonFormatter())
        logger.addHandler(h)
        logger.setLevel(os.getenv("SENTINEL_LOG", "WARNING").upper())
        logger.propagate = False
    return logger
