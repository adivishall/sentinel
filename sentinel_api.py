"""Sentinel HTTP API -- a small, dependency-free application surface.

Wraps the SAME firewall pipeline the evaluation harness uses (no parallel
logic) behind a JSON API, so the exact controls proven in ``make offline`` are
what an integrator would call:

    POST /api/evaluate     evaluate one dispute or KYB submission
    GET  /health           liveness
    GET  /version          name / version / mode / model
    GET  /api/audit/<id>    fetch a persisted audit event by request/audit id

Design notes
------------
* Built on the standard library only (``http.server``) -- offline mode needs no
  network, no API key, and no third-party framework.
* ``evaluate()`` is a pure function so it can be unit-tested without a socket.
* Optional bearer-token auth: if ``SENTINEL_API_KEY`` is set, requests must send
  ``Authorization: Bearer <key>`` (or ``X-API-Key: <key>``). Unset => open, for
  local/offline use. Secrets are read from the environment, never logged.
* Fails safe and explicit: malformed JSON -> 400, unknown surface -> 400,
  oversized body -> 413, bad route -> 404, auth failure -> 401.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import llm
from agents import dispute_triage, kyb_review
from firewall import __version__, audit, kyb_adjudicate, pipeline
from firewall.logging_config import get_logger

_log = get_logger("sentinel.api")

MAX_BODY = 64 * 1024  # 64 KB request cap; normalize() also caps submission length
VALID_SURFACES = ("dispute", "kyb")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _require(payload: dict, key: str, alt: str | None = None) -> object:
    if key in payload:
        return payload[key]
    if alt and alt in payload:
        return payload[alt]
    raise ApiError(400, f"missing required field: {key!r}")


def evaluate(payload: dict) -> dict:
    """Run one evaluation and return the canonical Decision dict.

    payload = {
      "surface": "dispute" | "kyb",
      "submission"/"application": "<untrusted text>",
      "document": "<optional untrusted document text>",
      "ledger"/"records": { ...verified facts... },
      "layers": ["L1","L2","L3","L4"],   # optional
      "persist_audit": true|false          # optional (default true)
    }
    """
    if not isinstance(payload, dict):
        raise ApiError(400, "request body must be a JSON object")

    surface = str(payload.get("surface", "dispute")).lower()
    if surface not in VALID_SURFACES:
        raise ApiError(400, f"invalid surface {surface!r}; expected one of {VALID_SURFACES}")

    layers = payload.get("layers", pipeline.ALL)
    if not isinstance(layers, (list, tuple)) or any(x not in pipeline.ALL for x in layers):
        raise ApiError(400, f"invalid layers; allowed: {list(pipeline.ALL)}")
    persist = bool(payload.get("persist_audit", True))

    # An uploaded document is untrusted content, appended to the submission text.
    document = payload.get("document")
    if document is not None and not isinstance(document, str):
        raise ApiError(400, "document must be a string")

    if surface == "dispute":
        text = str(_require(payload, "submission", "application"))
        facts = _require(payload, "ledger", "records")
        if not isinstance(facts, dict):
            raise ApiError(400, "ledger must be a JSON object")
        if document:
            text = f"{text}\n\n[UPLOADED DOCUMENT]\n{document}"
        d = pipeline.run_guarded(
            dispute_triage.run, text, facts, layers, surface="dispute", persist_audit=persist
        )
    else:  # kyb
        text = str(_require(payload, "application", "submission"))
        facts = _require(payload, "records", "ledger")
        if not isinstance(facts, dict):
            raise ApiError(400, "records must be a JSON object")
        if document:
            text = f"{text}\n\n[UPLOADED DOCUMENT]\n{document}"
        d = pipeline.run_guarded(
            kyb_review.run,
            text,
            facts,
            layers,
            adjudicator=kyb_adjudicate.adjudicate,
            effect_map=pipeline.KYB_EFFECT_MAP,
            surface="kyb",
            persist_audit=persist,
        )
    return d.to_dict()


def version_info() -> dict:
    return {
        "name": "sentinel",
        "version": __version__,
        "mode": llm.mode(),
        "model": llm.MODEL if llm.mode() == "live" else "offline-simulator",
    }


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------
def _authorized(headers) -> bool:
    key = os.environ.get("SENTINEL_API_KEY")
    if not key:
        return True  # open in offline/local mode
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer ") and auth[7:].strip() == key:
        return True
    return headers.get("X-API-Key", "").strip() == key


class SentinelHandler(BaseHTTPRequestHandler):
    server_version = f"Sentinel/{__version__}"

    def _send(self, status: int, obj: dict, request_id: str | None = None) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if request_id:
            self.send_header("X-Request-ID", request_id)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # route through structured logger, no secrets
        _log.info("http", extra={"detail": (fmt % args)})

    def do_GET(self) -> None:
        if self.path in ("/health", "/api/health"):
            return self._send(200, {"status": "ok", "mode": llm.mode()})
        if self.path in ("/version", "/api/version"):
            return self._send(200, version_info())
        if self.path.startswith("/api/audit/"):
            if not _authorized(self.headers):
                return self._send(401, {"error": "unauthorized"})
            audit_id = self.path.rsplit("/", 1)[-1]
            for ev in audit.read_all():
                if ev.get("audit_id") == audit_id or ev.get("request_id") == audit_id:
                    return self._send(200, ev)
            return self._send(404, {"error": f"audit event {audit_id!r} not found"})
        return self._send(404, {"error": "not found", "path": self.path})

    def do_POST(self) -> None:
        if self.path not in ("/api/evaluate", "/evaluate"):
            return self._send(404, {"error": "not found", "path": self.path})
        if not _authorized(self.headers):
            return self._send(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._send(400, {"error": "invalid Content-Length"})
        if length > MAX_BODY:
            return self._send(413, {"error": f"request too large (> {MAX_BODY} bytes)"})
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError as e:
            return self._send(400, {"error": f"invalid JSON: {e}"})
        try:
            result = evaluate(payload)
        except ApiError as e:
            return self._send(e.status, {"error": e.message})
        except Exception as e:  # noqa: BLE001 - never leak a stack trace to the client
            _log.warning("evaluate failed", extra={"detail": type(e).__name__})
            return self._send(500, {"error": "internal error"})
        return self._send(200, result, request_id=result.get("request_id"))


def serve(port: int = 8000, host: str = "0.0.0.0") -> None:
    httpd = ThreadingHTTPServer((host, port), SentinelHandler)
    auth = "on" if os.environ.get("SENTINEL_API_KEY") else "off (open)"
    print(f"Sentinel API v{__version__} on http://{host}:{port}  mode={llm.mode()}  auth={auth}")
    print("  POST /api/evaluate | GET /health | GET /version | GET /api/audit/<id>")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    serve(int(os.environ.get("PORT", "8000")))
