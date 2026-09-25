"""Static file serving never escapes the console directory."""

from __future__ import annotations

from datetime import datetime, timedelta

T0 = datetime(2026, 9, 1, 12, 0)


def _iso(days: float = 0, hours: float = 0) -> str:
    return (T0 + timedelta(days=days, hours=hours)).isoformat()


# ---- static path containment -------------------------------------------------------------
def test_static_file_serving_rejects_traversal(tmp_path, monkeypatch):
    import io

    from sentinel.api import server as srv

    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<html>ok</html>")
    (tmp_path / "ui2").mkdir()
    (tmp_path / "ui2" / "leak.txt").write_text("secret")
    (tmp_path / "secret.txt").write_text("secret")
    monkeypatch.setattr(srv, "UI_DIR", ui)

    class H(srv.SentinelHandler):
        def __init__(self):  # noqa: D401 - bypass socket setup
            self.wfile = io.BytesIO()
            self.sent: list[int] = []

        def send_response(self, code, message=None):
            self.sent.append(code)

        def send_header(self, *a):
            pass

        def end_headers(self):
            pass

    for bad in (
        "/ui/../secret.txt",
        "/../secret.txt",
        "/ui/../ui2/leak.txt",
        "/ui/%2e%2e/secret.txt",
    ):
        h = H()
        assert h._static(bad) is False, bad
    h = H()
    assert h._static("/index.html") is True and h.sent == [200]
