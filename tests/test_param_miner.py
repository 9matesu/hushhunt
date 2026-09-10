import pytest

from hushhunt.param_miner import find_hidden_params


def test_find_hidden_params_detects_differential_status_and_reflection():
    import httpx

    def handler(request: httpx.Request):
        url = str(request.url)
        if "debug=true" in url:
            return httpx.Response(200, text="DEBUG_MODE_ENABLED: secret config dump", headers={"X-Debug": "1"})
        if "redirect=" in url:
            return httpx.Response(302, headers={"Location": "https://attacker.invalid"})
        # Normal baseline response
        return httpx.Response(200, text="Standard public portal")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    results = find_hidden_params(client, "https://t.invalid/app", candidate_params=["debug", "redirect", "dummy"])

    params_found = [r["param"] for r in results]
    assert "debug" in params_found
    assert "redirect" in params_found
    assert "dummy" not in params_found
