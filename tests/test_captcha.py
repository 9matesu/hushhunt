from unittest.mock import MagicMock
import httpx
import pytest
from hushhunt.captcha import solve_captcha, extract_sitekey


def test_extract_sitekey():
    html = '<div class="g-recaptcha" data-sitekey="6Ld123TestSiteKey"></div>'
    key, kind = extract_sitekey(html)
    assert key == "6Ld123TestSiteKey"
    assert kind == "recaptcha"

    cf_html = '<div class="cf-turnstile" data-sitekey="0x4AAAATurnstileKey"></div>'
    key2, kind2 = extract_sitekey(cf_html)
    assert key2 == "0x4AAAATurnstileKey"
    assert kind2 == "turnstile"

    none_html = '<form><input name="user"></form>'
    assert extract_sitekey(none_html) == (None, None)


def test_solve_captcha_requires_api_key(monkeypatch):
    monkeypatch.delenv("HH_CAPTCHA_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="HH_CAPTCHA_API_KEY"):
        solve_captcha("https://example.com/signup", "testkey", "recaptcha", api_key=None)


def test_solve_captcha_flow_mock(monkeypatch):
    monkeypatch.setenv("HH_CAPTCHA_API_KEY", "dummy_solver_key")

    def handler(req):
        url_str = str(req.url)
        if "in.php" in url_str:
            return httpx.Response(200, text="OK|TASK_99999")
        if "res.php" in url_str:
            return httpx.Response(200, text="OK|TOKEN_SOLVED_ABC_123")
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    token = solve_captcha(
        page_url="https://example.com/signup",
        sitekey="6LdTestKey",
        captcha_type="recaptcha",
        client=client,
        poll_interval=0.01,
    )
    assert token == "TOKEN_SOLVED_ABC_123"
