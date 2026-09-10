import re

import pytest

from hushhunt.spaminer import extract_api_routes, extract_script_urls

HTML = """
<html><head>
<script src="/static/js/main.abc123.js"></script>
<script src="https://cdn.t.invalid/vendor.js"></script>
<script>var x = 1;</script>
</head><body></body></html>
"""


def test_extract_script_urls():
    urls = extract_script_urls(HTML, "https://t.invalid/")
    assert "https://t.invalid/static/js/main.abc123.js" in urls
    assert "https://cdn.t.invalid/vendor.js" in urls
    assert len(urls) == 2  # inline script ignored


def test_extract_api_routes_from_js():
    js = """
    fetch("/api/v1/orders?user=1");
    axios.post('/graphql', {query: '{ user { id } }'});
    const u = "https://t.invalid/api/profile";
    """
    routes = extract_api_routes(js)
    assert "/api/v1/orders" in routes
    assert "/graphql" in routes
    assert "https://t.invalid/api/profile" in routes
