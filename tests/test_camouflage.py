import pytest

from hushhunt.camouflage import get_camouflaged_transport, make_client


def test_make_client_with_standard_transport():
    import httpx
    # When transport is passed (offline test), it must be preserved
    fake = httpx.MockTransport(lambda r: httpx.Response(200, text="ok"))
    client = make_client(transport=fake, headers={"User-Agent": "test"})
    r = client.get("https://t.invalid")
    assert r.status_code == 200
    assert r.text == "ok"


def test_get_camouflaged_transport_signature():
    # Returns None or a valid transport depending on curl_cffi availability
    transport = get_camouflaged_transport("chrome124")
    # Must not crash
    assert transport is None or hasattr(transport, "handle_request")
