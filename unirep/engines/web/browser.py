"""Read-only browser inspection for sites the operator is authorized to assess.

No authentication, CAPTCHA, paywall, rate-limit or browser security bypasses.
Only page structure and sanitized request/response metadata are recorded.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse
from unirep.core.engine import AnalysisEngine
from unirep.core.models import AnalysisTarget, EngineResult, Evidence


def _safe_url(value: str) -> str:
    parsed = urlparse(value)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


class BrowserInspectionEngine(AnalysisEngine):
    name = "web_browser"
    description = "Read-only rendered-page and network-metadata inspection using optional Playwright."
    supported_kinds = {"url"}

    def analyze(self, target: AnalysisTarget, options: dict[str, Any] | None = None) -> EngineResult:
        if not target.authorized:
            raise PermissionError("Set authorized=True only for a site you own or are permitted to assess.")
        parsed = urlparse(target.value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Target must be an absolute http(s) URL")
        opts = options or {}
        timeout_ms = min(max(int(opts.get("timeout_ms", 20000)), 1000), 60000)
        allowed_hosts = {parsed.hostname.lower(), *(str(x).lower() for x in opts.get("allowed_hosts", []))}
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Install optional dependency: pip install '.[web]' and run playwright install chromium") from exc

        requests: list[dict[str, str]] = []
        responses: list[dict[str, Any]] = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            def guard_route(route):
                host = (urlparse(route.request.url).hostname or "").lower()
                if host not in allowed_hosts:
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", guard_route)
            page.on("request", lambda req: requests.append({
                "method": req.method, "url": _safe_url(req.url),
                "resource_type": req.resource_type
            }) if len(requests) < 500 else None)
            page.on("response", lambda res: responses.append({
                "status": res.status, "url": _safe_url(res.url)
            }) if len(responses) < 500 else None)
            try:
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
                        text: (a.innerText || '').trim().slice(0,160), href: a.href.split('?')[0].split('#')[0]
                    })),
                    forms: [...document.forms].slice(0,50).map(f => ({
                        method: (f.method || 'get').toUpperCase(),
                        action: f.action.split('?')[0].split('#')[0],
                        fields: [...f.elements].slice(0,50).map(e => ({
                            tag: e.tagName.toLowerCase(), type: e.type || null, name: e.name || null
                        }))
                    })),
                    scripts: [...document.scripts].slice(0,100).map(s => s.src ? s.src.split('?')[0] : '[inline]')
                })""")
            finally:
                context.close()
                browser.close()

        return EngineResult(
            engine=self.name, status="ok",
            summary=f"Inspected rendered page: {page_info.get('title') or parsed.hostname}",
            findings={
                "http_status": response.status if response else None,
                "final_url": _safe_url(page_info["url"]),
                "page": page_info,
                "requests": requests,
                "responses": responses,
                "network_capture_truncated": len(requests) >= 500 or len(responses) >= 500,
            },
            evidence=[Evidence(claim="Rendered page structure and response metadata observed",
                              source=_safe_url(page_info["url"]), confidence=0.95)],
            warnings=[
                "Read-only DOM inspection only; no application internals or server-side code are exposed.",
                "Cross-host requests are blocked unless their hosts are explicitly allowlisted.",
                "Query strings and URL fragments are removed from captured network metadata."
            ],
            confidence=0.95
        )
