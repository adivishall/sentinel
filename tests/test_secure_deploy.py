"""Secure-by-default deployment (issue #20).

An authoritative service reachable from the network must not run without authentication
by accident: loopback by default; a non-loopback bind needs an API key, or an explicit,
logged and audited ``--insecure-demo``. Browsers elsewhere cannot drive the loopback
default (JSON-only, same-origin POSTs). The configuration a server ran with is chained
into the audit log, and a reload of the trust store / reviewer registry is deliberate,
audited, and keeps the old configuration when the new one does not load.
"""

from __future__ import annotations

import inspect
import json
import os
import signal
import threading
import urllib.error
import urllib.request

import pytest

from sentinel.api import server as srv
from sentinel.api.server import InsecureBindError, check_bind, make_server, serve
from sentinel.app import SentinelApp
from sentinel.trust.issuer import Issuer
from sentinel.trust.keys import TrustStore
from tests.reviewers import registry

KEY = "k" * 32


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    for v in ("SENTINEL_API_KEY", "SENTINEL_API_KEY_FILE", "SENTINEL_INSECURE_DEMO"):
        monkeypatch.delenv(v, raising=False)
    srv._KEY_FILE_CACHE.clear()


@pytest.fixture(scope="module")
def app():
    return SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)


# ---- the bind ----------------------------------------------------------------------------------
def test_serve_defaults_to_loopback():
    assert inspect.signature(serve).parameters["host"].default == "127.0.0.1"
    assert inspect.signature(make_server).parameters["host"].default == "127.0.0.1"


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.0.0.2"])
def test_loopback_needs_no_key(host):
    assert check_bind(host) == "loopback"


@pytest.mark.parametrize("host", ["0.0.0.0", "", "::", "10.0.0.5", "sentinel.internal"])
def test_a_network_bind_without_a_key_is_refused(host, app):
    with pytest.raises(InsecureBindError, match="without authentication"):
        check_bind(host)
    with pytest.raises(InsecureBindError):
        make_server(app, host, 0)  # refused before any socket is opened


def test_a_network_bind_with_a_key_or_the_explicit_flag_is_allowed(monkeypatch):
    assert check_bind("0.0.0.0", insecure_demo=True) == "network"
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    assert check_bind("0.0.0.0") == "network"


def test_a_short_key_does_not_protect_a_network_bind(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "secret")
    with pytest.raises(InsecureBindError, match="shorter than 16"):
        check_bind("0.0.0.0")
    assert check_bind("127.0.0.1") == "loopback"


def test_the_key_can_come_from_a_mounted_file(tmp_path, monkeypatch):
    f = tmp_path / "api_key"
    f.write_text(KEY + "\n")
    monkeypatch.setenv("SENTINEL_API_KEY_FILE", str(f))
    assert srv.api_key() == KEY and check_bind("0.0.0.0") == "network"


def test_the_cli_refuses_an_open_network_bind(capsys):
    from sentinel.cli.main import main

    assert main(["--db", ":memory:", "serve", "--host", "0.0.0.0", "--port", "0"]) == 2
    assert "without authentication" in capsys.readouterr().err


# ---- requests ----------------------------------------------------------------------------------
@pytest.fixture()
def live(app):
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _req(url, *, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read() or b"{}")


BODY = json.dumps({"case_type": "dispute", "title": "t"}).encode()


@pytest.mark.parametrize("ctype", [None, "text/plain", "application/x-www-form-urlencoded"])
def test_a_post_that_is_not_json_is_refused(live, ctype):
    """A page elsewhere can send these without a CORS preflight."""
    headers = {"Content-Type": ctype} if ctype else {}
    if ctype is None:  # urllib would add form-encoding: send it raw
        headers = {"Content-Type": ""}
    status, _, body = _req(
        live + "/v1/policies/evaluate", method="POST", body=BODY, headers=headers
    )
    assert status == 415 and "application/json" in body["error"]


@pytest.mark.parametrize(
    "extra",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_a_cross_site_post_is_refused(live, extra):
    status, _, _ = _req(
        live + "/v1/policies/evaluate",
        method="POST",
        body=BODY,
        headers={"Content-Type": "application/json", **extra},
    )
    assert status == 403


def test_a_same_origin_post_is_served(live):
    host = live.split("//", 1)[1]
    status, _, _ = _req(
        live + "/v1/policies/evaluate",
        method="POST",
        body=json.dumps({"policy_id": "dispute-refund", "context": {}}).encode(),
        headers={"Content-Type": "application/json", "Origin": f"http://{host}"},
    )
    assert status != 403 and status != 415


def test_a_negative_content_length_is_a_400(live):
    import http.client

    port = int(live.rsplit(":", 1)[1])
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", "/v1/policies/evaluate")
    c.putheader("Content-Type", "application/json")
    c.putheader("Content-Length", "-5")
    c.endheaders()
    assert c.getresponse().status == 400


def test_security_headers_and_a_csp_on_the_console(live):
    with urllib.request.urlopen(live + "/", timeout=10) as r:
        h = r.headers
        assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert "script-src 'self'" in h["Content-Security-Policy"]
    for k, v in (("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer")):
        assert h[k] == v
    _, headers, _ = _req(live + "/health")
    assert headers["X-Frame-Options"] == "DENY" and "X-Sentinel-Insecure-Demo" not in headers


def test_version_and_system_do_not_reveal_more_than_they_need(live):
    _, _, v = _req(live + "/version")
    assert set(v) == {"name", "version"}  # unauthenticated: no provider, no model
    _, _, s = _req(live + "/v1/system")
    assert "/" not in s["store"]  # a file name at most, never a path on disk


# ---- the record of how the server ran ---------------------------------------------------------
def test_server_start_is_audited_without_secrets(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    reg, tokens = registry(("alice", "HUMAN_REVIEWER", 1000))
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    started = threading.Event()
    real = srv.ThreadingHTTPServer.serve_forever

    def once(self, *a, **kw):  # stop at once: the start is what is under test
        started.set()

    monkeypatch.setattr(srv.ThreadingHTTPServer, "serve_forever", once)
    serve(app, "0.0.0.0", 0)
    monkeypatch.setattr(srv.ThreadingHTTPServer, "serve_forever", real)
    ev = [e for e in app.runtime.audit.events() if e.action == "SERVER_START"][-1]
    d = ev.detail
    assert ev.kind == "system" and d["bind"] == "network" and d["auth"] == "api_key"
    assert d["insecure_demo"] is False and d["reviewers"]["active"] == ["alice"]
    blob = json.dumps(ev.to_dict())
    assert KEY not in blob and tokens["alice"] not in blob
    assert app.verify_audit().ok


def test_an_insecure_demo_is_marked_on_every_response_and_audited(app, monkeypatch, capsys):
    httpd = make_server(app, "0.0.0.0", 0, insecure_demo=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _, headers, _ = _req(f"http://127.0.0.1:{httpd.server_address[1]}/health")
        assert headers["X-Sentinel-Insecure-Demo"] == "1"
    finally:
        httpd.shutdown()
    cfg = srv.server_config(app, "0.0.0.0", 0, insecure_demo=True)
    assert cfg["insecure_demo"] is True and cfg["auth"] == "open"


# ---- reload ------------------------------------------------------------------------------------
def _trust_file(tmp_path, *issuers):
    f = tmp_path / "trust.json"
    store = TrustStore.empty()
    for i in issuers:
        store = store.with_key(Issuer.ephemeral(i).key)
    f.write_text(store.dumps())
    return f


def test_a_reload_swaps_in_a_new_trust_store_and_is_audited(tmp_path):
    f = _trust_file(tmp_path, "ledger-a")
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)
    app.trust_source = str(f)
    before = set(app.runtime.trust.keys)
    newer = TrustStore.load(f).with_key(Issuer.ephemeral("ledger-b").key)
    f.write_text(newer.dumps())
    d = app.reload_config("test")
    assert d["outcome"] == "reloaded" and len(d["trust"]["added"]) >= 1
    assert set(newer.keys) <= set(app.runtime.trust.keys)
    assert app.issuer.key.key_id in app.runtime.trust.keys  # the demo issuer stays trusted
    assert app.what_if_runtime.trust is app.runtime.trust
    assert set(app.runtime.trust.keys) != before
    ev = [e for e in app.runtime.audit.events() if e.action == "CONFIG_RELOAD"][-1]
    assert ev.detail["source"] == "test" and ev.detail["trust"]["sha256"]


def test_a_reload_that_fails_keeps_the_running_configuration(tmp_path):
    f = _trust_file(tmp_path, "ledger-a")
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)
    app.trust_source = str(f)
    app.reload_config("test")
    running = dict(app.runtime.trust.keys)
    f.write_text('{"format": "sentinel.trust-store/1", "keys": [{"oops": 1}]}')
    d = app.reload_config("test")
    assert d["outcome"] == "refused"
    assert app.runtime.trust.keys == running  # nothing new trusted, nothing dropped
    ev = [e for e in app.runtime.audit.events() if e.action == "CONFIG_RELOAD_FAILED"][-1]
    assert ev.detail["outcome"] == "refused"


def test_a_reload_deactivates_a_reviewer_from_the_registry_file(tmp_path):
    reg, tokens = registry(("alice", "HUMAN_REVIEWER", 1000), ("bob", "HUMAN_REVIEWER", 1000))
    f = tmp_path / "reviewers.json"
    f.write_text(reg.dumps())
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    app.reviewers_source = str(f)
    f.write_text(reg.deactivate("bob").dumps())
    d = app.reload_config("sighup")
    assert d["reviewers"]["deactivated"] == ["bob"]
    assert app.reviewers.authenticate(tokens["bob"]) is None
    assert app.reviewers.authenticate(tokens["alice"]).reviewer_id == "alice"


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="no SIGHUP on this platform")
def test_sighup_reloads(tmp_path, monkeypatch):
    f = _trust_file(tmp_path, "ledger-a")
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)
    app.trust_source = str(f)
    monkeypatch.setattr(srv.ThreadingHTTPServer, "serve_forever", lambda self, *a, **k: None)
    old = signal.getsignal(signal.SIGHUP)
    try:
        serve(app, "127.0.0.1", 0)
        os.kill(os.getpid(), signal.SIGHUP)
        assert any(e.action == "CONFIG_RELOAD" for e in app.runtime.audit.events())
    finally:
        signal.signal(signal.SIGHUP, old)
