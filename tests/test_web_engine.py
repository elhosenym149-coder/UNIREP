import pytest
from unirep.core.models import AnalysisTarget
from unirep.engines.web.browser import BrowserInspectionEngine


def test_browser_engine_requires_explicit_authorization():
    engine = BrowserInspectionEngine()
    with pytest.raises(PermissionError):
        engine.analyze(AnalysisTarget("https://example.org", "url", authorized=False))


def test_browser_engine_rejects_non_http_scheme():
    engine = BrowserInspectionEngine()
    with pytest.raises(ValueError):
        engine.analyze(AnalysisTarget("file:///etc/passwd", "url", authorized=True))


def test_safe_url_removes_credentials_query_and_fragment():
    from unirep.engines.web.browser import _safe_url
    assert _safe_url("https://user:secret@example.org/path?token=abc#fragment") == "https://example.org/path"
