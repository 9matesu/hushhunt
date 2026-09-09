import httpx

from tests.vulnapp import handler, safe_handler

_PW = "hu" + "sh"   # the mock app accepts exactly this password


def test_search_reflects_raw():
    req = httpx.Request("GET", "https://t.invalid/search?q=<b>hi</b>")
    r = handler(req)
    assert "<b>hi</b>" in r.text           # vulnerable echo


def test_safe_handler_escapes():
    req = httpx.Request("GET", "https://t.invalid/search?q=<b>hi</b>")
    r = safe_handler(req)
    assert "<b>hi</b>" not in r.text and "&lt;b&gt;" in r.text


def test_login_flow_sets_session_and_jwt():
    c = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    page = c.get("https://t.invalid/login")
    assert 'value="tok123"' in page.text
    r = c.post("https://t.invalid/login", data={
        "username": "acct_a", "password": _PW, "authenticity_token": "tok123"})
    assert r.status_code == 302
    assert r.headers["X-JWT"].startswith("eyJ")
    orders = c.get("https://t.invalid/api/orders/1")
    assert orders.status_code == 200 and orders.json()["owner"] == "acct_a"


def test_idor_vulnerable_any_session_reads_order2():
    c = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    c.get("https://t.invalid/login")
    c.post("https://t.invalid/login", data={"username": "acct_b",
                                            "password": _PW,
                                            "authenticity_token": "tok123"})
    o = c.get("https://t.invalid/api/orders/1")   # acct_b reads acct_a's order
    assert o.status_code == 200 and o.json()["owner"] == "acct_a"


def test_idor_safe_handler_blocks_cross_read():
    c = httpx.Client(transport=httpx.MockTransport(safe_handler),
                     follow_redirects=False)
    c.get("https://t.invalid/login")
    c.post("https://t.invalid/login", data={"username": "acct_b",
                                            "password": _PW,
                                            "authenticity_token": "tok123"})
    assert c.get("https://t.invalid/api/orders/1").status_code == 403
    assert c.get("https://t.invalid/api/orders/2").status_code == 200


def test_sqli_and_ssti_surfaces():
    assert "pg_query" in handler(httpx.Request(
        "GET", "https://t.invalid/item?id=1'")).text
    long_true = handler(httpx.Request(
        "GET", "https://t.invalid/item?id=1' AND 1=1--")).text
    short_false = handler(httpx.Request(
        "GET", "https://t.invalid/item?id=1' AND 1=2--")).text
    assert len(long_true) > 2 * len(short_false)
    assert "49" in handler(httpx.Request(
        "GET", "https://t.invalid/render?tpl={{7*7}}")).text
    assert "49" not in handler(httpx.Request(
        "GET", "https://t.invalid/render?tpl=xyz")).text
