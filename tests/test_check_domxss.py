import httpx

from hushhunt.checks import Ctx
from hushhunt.checks.active.domxss import check_dom_xss
import hushhunt.checks.active.domxss  # registration side-effect is enough

VULN_JS = ("const p=location.hash.slice(1);"
           "document.getElementById('x').innerHTML=p;")
SAFE_JS = "const p=location.hash.slice(1);" \
          "document.getElementById('x').textContent=p;"


def test_chain_detected_with_zero_requests():
    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", "https://t.invalid/")),
              fetch=None)
    ctx.fetched_js = [("https://t.invalid/a.js", VULN_JS)]
    out = check_dom_xss(ctx)
    assert len(out) == 1
    assert out[0]["check_id"] == "xss_dom"
    assert out[0]["payload"]["sink"] == "innerHTML"
    assert out[0]["payload"]["source"] == "location.hash"


def test_textcontent_safe_no_signal():
    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", "https://t.invalid/")),
              fetch=None)
    ctx.fetched_js = [("https://t.invalid/a.js", SAFE_JS)]
    assert check_dom_xss(ctx) == []


def test_dedup_same_chain():
    ctx = Ctx(resp=httpx.Response(200, request=httpx.Request("GET", "https://t.invalid/")),
              fetch=None)
    ctx.fetched_js = [("https://t.invalid/a.js", VULN_JS + VULN_JS)]
    assert len(check_dom_xss(ctx)) == 1
