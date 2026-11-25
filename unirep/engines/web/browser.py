"""Read-only browser inspection for sites the operator is authorized to assess.

This engine deliberately does not bypass authentication, CAPTCHAs, paywalls,
rate limits, or browser security controls. It records rendered structure and
navigation metadata only; it does not submit forms or trigger destructive actions.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult


class BrowserInspectionEngine(AnalysisEngine):
    name = "web_browser"
    description = "Read-only rendered-page inspection using optional Playwright."
    supported_kinds = {"url"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        if not target.authorized:
            raise PermissionError("Set authorized=True only for a site you own or are permitted to assess.")
        parsed = urlparse(target.value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Target must be an absolute http(s) URL")
        opts = options or {}
        timeout_ms = min(max(int(opts.get("timeout_ms", 20000)), 1000), 60000)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Install optional dependency: pip install '.[web]'") from exc

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            response = page.goto(target.value, wait_until="domcontentloaded", timeout=timeout_ms)
            page_info = page.evaluate("""() => ({
                title: document.title,
                url: location.href,
                language: document.documentElement.lang || null,
                viewport: {width: innerWidth, height: innerHeight},
                headings: [...document.querySelectorAll('h1,h2,h3')].slice(0,100).map(x => ({
                    level: x.tagName.toLowerCase(), text: (x.innerText || '').trim().slice(0,300)
                })),
                links: [...document.querySelectorAll('a[href]')].slice(0,250).map(a => ({
                    text: (a.innerText || '').trim().slice(0,160), href: a.href
                })),
                forms: [...document.forms].slice(0,50).map(f => ({
                    method: (f.method || 'get').toUpperCase(),
                    action: f.action,
                    fields: [...f.elements].slice(0,50).map(e => ({
                        tag: e.tagName.toLowerCase(), type: e.type || null, name: e.name || null
                    }))
                })),
                scripts: [...document.scripts].slice(0,100).map(s => s.src || '[inline]')
            })""")
            browser.close()
        return EngineResult(
            engine=self.name, status="ok",
            summary=f"Inspected rendered page: {page_info.get('title') or parsed.hostname}",
            findings={"http_status": response.status if response else None,
                      "final_url": page_info["url"], "page": page_info},
            warnings=["Read-only DOM inspection only; no application internals or server-side code are exposed."],
            confidence=0.95
        )
