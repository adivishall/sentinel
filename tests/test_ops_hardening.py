"""Operator-facing defects found by the release audit (deployment persona)."""

from __future__ import annotations

import argparse
from pathlib import Path

from sentinel.api import server as srv
from sentinel.app import SentinelApp
from sentinel.cli.main import _app, main


def test_a_read_only_command_never_creates_or_seeds_a_store(tmp_path, capsys):
    """`audit verify --db <typo>` created the file, seeded 5,000 synthetic transactions
    and printed "audit chain: OK"."""
    db = tmp_path / "typo.db"
    assert main(["--db", str(db), "audit", "verify"]) != 0
    assert "no store at" in capsys.readouterr().err
    assert not db.exists()


def test_a_named_store_gets_synthetic_data_only_on_request(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_DEMO_DATA", raising=False)
    prod = _app(argparse.Namespace(db=str(tmp_path / "prod.db"), command="analyze"))
    assert prod.store.count("transactions") == 0
    demo = _app(argparse.Namespace(db=str(tmp_path / "demo.db"), command="analyze", demo_data=True))
    assert demo.store.count("transactions") > 0


def test_the_console_is_found_when_the_package_is_installed(tmp_path, monkeypatch):
    """An installed package has no ui/ beside it: the console was a 404 in the image."""
    installed = tmp_path / "site-packages" / "sentinel" / "api" / "server.py"
    (tmp_path / "ui").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SENTINEL_UI_DIR", raising=False)
    found = srv._asset_dir("ui", "SENTINEL_UI_DIR", here=installed)
    assert found.resolve() == (tmp_path / "ui").resolve()
    monkeypatch.setenv("SENTINEL_UI_DIR", "/opt/sentinel/ui")
    assert srv._asset_dir("ui", "SENTINEL_UI_DIR", here=installed) == Path("/opt/sentinel/ui")


def test_a_key_overrides_the_insecure_demo_flag(monkeypatch):
    """A keyed server started with --insecure-demo recorded insecure_demo=True and printed
    "WITHOUT authentication"."""
    monkeypatch.setenv("SENTINEL_API_KEY", "k" * 24)
    app = SentinelApp.demo(seed=4, customers=10, merchants=3, transactions=60)
    cfg = srv.server_config(app, "0.0.0.0", 8000, insecure_demo=True)
    assert cfg["auth"] == "api_key" and cfg["insecure_demo"] is False
    monkeypatch.delenv("SENTINEL_API_KEY")
    assert srv.server_config(app, "0.0.0.0", 8000, insecure_demo=True)["insecure_demo"] is True


def test_an_unreadable_key_file_refuses_to_serve_and_fails_closed(tmp_path, monkeypatch, capsys):
    """A missing SENTINEL_API_KEY_FILE was a bare [Errno 2] with exit 1."""
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    monkeypatch.setenv("SENTINEL_API_KEY_FILE", str(tmp_path / "missing-secret"))
    assert main(["--db", ":memory:", "serve", "--host", "127.0.0.1", "--port", "0"]) == 2
    assert "cannot be read" in capsys.readouterr().err
    assert srv._authorized({}) is False  # every request refused, never served open


def test_audit_list_can_show_the_server_start_record(tmp_path, capsys):
    """The runbook says to check the SERVER_START event with `audit list`, which printed
    neither the event id nor its detail."""
    import json

    from sentinel.app import SentinelApp as App

    db = tmp_path / "s.db"
    app = App.open(str(db))
    app.runtime.audit.append(
        actor="sentinel",
        workflow="system",
        action="SERVER_START",
        kind="system",
        detail={"auth": "api_key", "insecure_demo": False},
    )
    assert main(["--db", str(db), "audit", "list", "--action", "SERVER_START", "--json"]) == 0
    events = json.loads(capsys.readouterr().out)
    assert [e["action"] for e in events] == ["SERVER_START"]
    assert events[0]["detail"]["auth"] == "api_key" and events[0]["event_id"]


def test_demo_reviewers_exist_behind_a_key_on_an_ephemeral_store_only(
    tmp_path, monkeypatch, capsys
):
    """A public demo (a network bind behind an API key, an in-memory store) needs the two
    demo reviewers for the console's case form; a persistent store never gets them."""
    served: list[SentinelApp] = []
    monkeypatch.setattr(srv, "serve", lambda app, *a, **k: served.append(app))
    monkeypatch.setenv("SENTINEL_API_KEY", "k" * 24)
    monkeypatch.delenv("SENTINEL_DEMO_DATA", raising=False)
    assert main(["--db", ":memory:", "serve", "--host", "0.0.0.0", "--port", "0"]) == 0
    err = capsys.readouterr().err
    assert "demo reviewer credentials" in err and "alice" in err and "sam" in err
    assert {r.reviewer_id for r in served[-1].reviewers.reviewers()} == {"alice", "sam"}
    # a persistent store behind the same key: no demo reviewers, with or without data
    db = str(tmp_path / "s.db")
    assert main(["--db", db, "serve", "--host", "0.0.0.0", "--port", "0"]) == 0
    err = capsys.readouterr().err
    assert "demo reviewer" not in err and served[-1].reviewers.reviewers() == []
    assert (
        main(
            [
                "--db",
                db,
                "data",
                "generate",
                "--seed",
                "1",
                "--customers",
                "5",
                "--merchants",
                "2",
                "--transactions",
                "20",
            ]
        )
        == 0
    )
    assert main(["--db", db, "serve", "--host", "0.0.0.0", "--port", "0"]) == 0
    assert "demo reviewer" not in capsys.readouterr().err
    assert served[-1].reviewers.reviewers() == []
    # and still, with no key and no --insecure-demo, a network bind never serves at all
    monkeypatch.delenv("SENTINEL_API_KEY")
    assert main(["--db", ":memory:", "serve", "--host", "0.0.0.0", "--port", "0"]) == 2
    assert len(served) == 3
