"""Browser smoke test for the console.

Every console view is loaded from the real API (in-process, in-memory demo
dataset) in headless Chromium and checked for:

* the view actually rendered (the header crumb matches, the body has content);
* no uncaught page error and no failed network request other than the
  optional /favicon.ico;
* no horizontal page overflow at 1280 px and at 390 px, which is the
  regression the issue mentions (a wide table without a scroll container made
  the Evaluations page overflow by 1,116 px in a 1,024 px viewport).

The test is optional: it is skipped cleanly when the ``playwright`` package or
its browser is not installed, so the normal ``pytest tests/`` run is unchanged.
Run it directly with::

    pip install playwright
    python -m playwright install chromium
    python -m pytest tests/test_console_playwright.py -q
"""

from __future__ import annotations

import threading

import pytest

pytest.importorskip("playwright.sync_api", reason="browser test needs `pip install playwright`")

from playwright.sync_api import sync_playwright  # noqa: E402

from sentinel.api.server import make_server  # noqa: E402
from sentinel.app import SentinelApp  # noqa: E402

VIEWS = [
    ("overview", "Overview"),
    ("transactions", "Transactions"),
    ("disputes", "Disputes"),
    ("aisecurity/document_injection", "AI Security"),
    ("replay/example", "Replay"),
    ("evaluations", "Evaluations"),
    ("system", "System"),
]

WIDTHS = [1280, 390]


@pytest.fixture(scope="module")
def console_url():
    app = SentinelApp.demo(seed=42, customers=20, merchants=6, transactions=300)
    app.analyze(
        transactions=15, disputes=5, applications=3, sessions=4, accounts=3, skip_agent=False
    )
    httpd = make_server(app, "127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except Exception as exc:  # browser binaries are optional
            pytest.skip(f"Playwright chromium is not installed: {exc}")
        try:
            yield instance
        finally:
            instance.close()


@pytest.mark.parametrize("route,heading", VIEWS, ids=[v[0] for v in VIEWS])
@pytest.mark.parametrize("width", WIDTHS, ids=[f"{w}px" for w in WIDTHS])
def test_console_view_renders_cleanly(browser, console_url, route, heading, width):
    page = browser.new_page(viewport={"width": width, "height": 900})
    page_errors: list[str] = []
    console_errors: list[str] = []
    bad_responses: list[tuple[int, str]] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    page.on(
        "console",
        lambda message: console_errors.append(message.text) if message.type == "error" else None,
    )
    page.on(
        "response",
        lambda response: (
            bad_responses.append((response.status, response.url))
            if response.status >= 400
            else None
        ),
    )

    try:
        page.goto(f"{console_url}/#{route}", wait_until="domcontentloaded")
        page.wait_for_function(
            "(heading) => document.querySelector('#crumb')?.textContent?.trim() === heading",
            arg=heading,
            timeout=15_000,
        )
        page.wait_for_function(
            "() => !document.querySelector('#view')?.innerHTML.includes('loading…')",
            timeout=20_000,
        )
        page.wait_for_timeout(700)  # let the replay/example click and any chart paint finish

        layout = page.evaluate("""() => ({
                heading: document.querySelector('#crumb')?.textContent?.trim() ?? '',
                body: (document.querySelector('#view')?.innerText ?? '').trim(),
                scrollWidth: document.documentElement.scrollWidth,
                clientWidth: document.documentElement.clientWidth,
            })""")

        assert layout["heading"] == heading
        assert len(layout["body"]) > 200, f"{route} rendered almost nothing"
        assert layout["scrollWidth"] <= layout["clientWidth"], (
            f"{route} overflows horizontally at {width}px: "
            f"{layout['scrollWidth']} > {layout['clientWidth']}"
        )
        assert page_errors == [], f"{route}: uncaught page error: {page_errors}"
        unexpected = [bad for bad in bad_responses if not bad[1].endswith("/favicon.ico")]
        assert unexpected == [], f"{route}: failed requests: {unexpected}"
        real_console_errors = [
            error for error in console_errors if "Failed to load resource" not in error
        ]
        assert real_console_errors == [], f"{route}: console errors: {real_console_errors}"
    finally:
        page.close()
