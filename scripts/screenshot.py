#!/usr/bin/env python3
"""Capture the investigation console for the README and docs (Playwright, headless Chromium).

Serves the pre-rendered static console (``scripts/build_static_demo.py docs/demo``) on
localhost, lets it auto-run the first investigation of the real OTRF fixture capture,
explains the first cited claim, and writes ``docs/assets/console.png``.

    pip install playwright && python -m playwright install chromium
    python scripts/build_static_demo.py docs/demo
    python scripts/screenshot.py
"""
from __future__ import annotations

import functools
import http.server
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "console.png"


def main() -> int:
    from playwright.sync_api import sync_playwright

    demo = ROOT / "docs" / "demo"
    if not (demo / "index.html").exists():
        raise SystemExit("build the static console first: python scripts/build_static_demo.py docs/demo")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT / "docs"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/demo/index.html"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 860}, device_scale_factor=1,
                                    color_scheme="light")
            page.goto(url)
            page.wait_for_selector("#facts button.claim", timeout=30_000)
            # explain a cited claim that two independent engines back (the point of the graph)
            buttons = page.locator("#report button.claim")
            for i in range(buttons.count()):
                buttons.nth(i).click()
                page.wait_for_function("document.querySelector('#explain').textContent.includes('independent')",
                                       timeout=30_000)
                text = page.locator("#explain").inner_text()
                if '"anvil"' in text and '"revenant"' in text:
                    break
            OUT.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(OUT), full_page=False)
            browser.close()
    finally:
        srv.shutdown()
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
