import pytest

from hushhunt.poc import generate_deterministic_poc, run_poc, validate_ast


def test_deterministic_poc_xss_reflected():
    signal = {
        "check_id": "xss_reflected",
        "asset": "https://target.test/search?q=%22%3Ehush123%22%3C",
        "payload": {"param": "q", "marker": "hush123", "encoded": False},
    }
    code = generate_deterministic_poc(signal)
    assert code is not None
    validate_ast(code)
    assert "hush123" in code
    assert "client.fetch" in code
    assert "result['ok'] = True" in code


def test_deterministic_poc_sqli_error():
    signal = {
        "check_id": "sqli_error",
        "asset": "https://target.test/item?id=1%27",
        "payload": {"param": "id", "db": "mysql", "pattern": "syntax error"},
    }
    code = generate_deterministic_poc(signal)
    validate_ast(code)
    assert "syntax error" in code.lower()
    assert "result['ok'] = True" in code


def test_deterministic_poc_ssti():
    signal = {
        "check_id": "ssti",
        "asset": "https://target.test/greet?name=%7B%7B7*7%7D%7D",
        "payload": {"param": "name", "expected": "49"},
    }
    code = generate_deterministic_poc(signal)
    validate_ast(code)
    assert "49" in code
    assert "result['ok'] = True" in code


def test_deterministic_poc_open_redirect():
    signal = {
        "check_id": "open_redirect_chain",
        "asset": "https://target.test/login?next=https://evil.test",
        "payload": {"param": "next", "target": "https://evil.test"},
    }
    code = generate_deterministic_poc(signal)
    validate_ast(code)
    assert "evil.test" in code
    assert "result['ok'] = True" in code
