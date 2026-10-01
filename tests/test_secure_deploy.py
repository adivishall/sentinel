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
from dataclasses import replace

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
        import time

        deadline = time.monotonic() + 10  # the reload runs on its own thread
        while time.monotonic() < deadline and not any(
            e.action == "CONFIG_RELOAD" for e in app.runtime.audit.events()
        ):
            time.sleep(0.02)
        assert any(e.action == "CONFIG_RELOAD" for e in app.runtime.audit.events())
    finally:
        signal.signal(signal.SIGHUP, old)


# ---- regressions: the adversarial review of #20 ------------------------------------------------
def _raw(port, path="/v1/system", *, method="GET", headers=None, body=None):
    import http.client

    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest(method, path, skip_host=True)
    for k, v in (headers or {}).items():
        c.putheader(k, v)
    if body is not None:
        c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    return c.getresponse().status


def test_r1_dns_rebinding_is_refused_by_the_host_check(live, monkeypatch):
    port = int(live.rsplit(":", 1)[1])
    evil = {"Host": f"rebind.attacker.test:{port}", "Origin": f"http://rebind.attacker.test:{port}"}
    assert _raw(port, headers=evil) == 421
    body = json.dumps({"case_type": "dispute", "title": "t"}).encode()
    post = {**evil, "Content-Type": "application/json"}
    assert _raw(port, "/v1/policies/evaluate", method="POST", headers=post, body=body) == 421
    for host in (f"127.0.0.1:{port}", f"localhost:{port}", "LOCALHOST"):
        assert _raw(port, headers={"Host": host}) == 200, host
    monkeypatch.setenv("SENTINEL_ALLOWED_HOSTS", "sentinel.example.com")
    assert _raw(port, headers={"Host": "sentinel.example.com"}) == 200
    # behind a proxy that rewrites Host to the upstream: the public Origin is accepted
    proxied = {
        "Host": f"127.0.0.1:{port}",
        "Origin": "https://sentinel.example.com",
        "Content-Type": "application/json",
    }
    assert _raw(port, "/v1/policies/evaluate", method="POST", headers=proxied, body=b"{}") != 403


def test_r9_a_malformed_origin_is_a_403_not_a_dropped_connection(live):
    port = int(live.rsplit(":", 1)[1])
    headers = {
        "Host": f"127.0.0.1:{port}",
        "Origin": "http://[",
        "Content-Type": "application/json",
    }
    assert _raw(port, "/v1/policies/evaluate", method="POST", headers=headers, body=b"{}") == 403


def test_r2_r3_reloads_happen_off_the_signal_handler_and_never_kill_the_server(
    tmp_path, monkeypatch
):
    """Two SIGHUPs 0.2 ms apart deadlocked the server (a re-entered handler took its own
    lock); a reload that raised anything but ValueError/OSError ended serve_forever."""
    import time

    f = _trust_file(tmp_path, "ledger-a")
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)
    app.trust_source = str(f)
    # a trust file naming the demo issuer's key with other settings: with_key raises
    conflicting = TrustStore.empty().with_key(replace(app.issuer.key, label="someone else's"))
    monkeypatch.setattr(srv.ThreadingHTTPServer, "serve_forever", lambda self, *a, **k: None)
    old = signal.getsignal(signal.SIGHUP)
    try:
        serve(app, "127.0.0.1", 0)
        os.kill(os.getpid(), signal.SIGHUP)
        os.kill(os.getpid(), signal.SIGHUP)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not any(
            e.action == "CONFIG_RELOAD" for e in app.runtime.audit.events()
        ):
            time.sleep(0.02)
        assert any(e.action == "CONFIG_RELOAD" for e in app.runtime.audit.events())
        f.write_text(conflicting.dumps())
        d = app.reload_config("test")  # raises inside: refused and audited, never thrown
        assert d["outcome"] == "refused" and "/" not in d["reason"]
    finally:
        signal.signal(signal.SIGHUP, old)


def test_r4_rotating_the_key_file_takes_effect_without_a_restart(tmp_path, monkeypatch):
    import time

    f = tmp_path / "api_key"
    f.write_text("A" * 32)
    monkeypatch.setenv("SENTINEL_API_KEY_FILE", str(f))
    assert srv.api_key() == "A" * 32
    time.sleep(0.01)
    f.write_text("B" * 32)
    os.utime(f, (time.time() + 5, time.time() + 5))  # a new mtime, whatever the clock grain
    assert srv.api_key() == "B" * 32


@pytest.mark.parametrize("blank", [" " * 16, "\t" * 20, "x" * 15 + " "])
def test_r6_a_blank_or_padded_key_is_not_a_key(monkeypatch, blank):
    monkeypatch.setenv("SENTINEL_API_KEY", blank)
    with pytest.raises(InsecureBindError):
        check_bind("0.0.0.0")


def test_r5_the_start_record_holds_no_key_fingerprint(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)
    cfg = srv.server_config(app, "0.0.0.0", 0, insecure_demo=False)
    assert cfg["api_key_source"] == "env" and "api_key_sha256_prefix" not in cfg
    import hashlib

    assert hashlib.sha256(KEY.encode()).hexdigest()[:12] not in json.dumps(cfg)


def test_r7_data_files_are_behind_the_key_and_the_console_code_is_not(monkeypatch, app):
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        h = {"Host": f"127.0.0.1:{port}"}
        assert _raw(port, "/", headers=h) == 200 and _raw(port, "/app.js", headers=h) == 200
        assert _raw(port, "/snapshot.json", headers=h) == 401
        assert _raw(port, "/snapshot.json", headers={**h, "Authorization": f"Bearer {KEY}"}) == 200
    finally:
        httpd.shutdown()


def test_r11_concurrent_connections_are_capped(monkeypatch, app):
    import socket as sk

    monkeypatch.setenv("SENTINEL_MAX_CONNECTIONS", "2")
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    held = [sk.create_connection(("127.0.0.1", port)) for _ in range(2)]  # idle, held open
    try:
        import time

        time.sleep(0.2)
        extra = sk.create_connection(("127.0.0.1", port))
        extra.settimeout(5)
        extra.sendall(b"GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        assert extra.recv(100) == b""  # closed at once, no thread held
        extra.close()
    finally:
        for s in held:
            s.close()
        httpd.shutdown()


def test_r12_system_info_names_files_not_paths(tmp_path):
    f = _trust_file(tmp_path, "ledger-a")
    app = SentinelApp.demo(
        seed=3, customers=10, merchants=4, transactions=80, trust=TrustStore.load(f)
    )
    assert "/" not in app.system_info()["trust"]["origin"]


def test_r13_an_ipv6_loopback_bind_works(app):
    import socket as sk

    if not sk.has_ipv6:
        pytest.skip("no IPv6")
    try:
        httpd = make_server(app, "::1", 0)
    except OSError:
        pytest.skip("IPv6 loopback unavailable here")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(
            f"http://[::1]:{httpd.server_address[1]}/health", timeout=10
        ) as r:
            assert r.status == 200
    finally:
        httpd.shutdown()
