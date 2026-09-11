from unittest.mock import MagicMock
import httpx
import pytest
from hushhunt.registration import register_account, RegistrationError


def test_register_account_policy_blocks_forbidden_program():
    policy = "You may not create test accounts. Use provided credentials."
    with pytest.raises(PermissionError, match="Registration forbidden by program policy"):
        register_account(
            signup_url="https://example.com/signup",
            login_url="https://example.com/login",
            program={"id": "test-p", "policy_text": policy, "includes": ["example.com"], "excludes": []},
            mailbox=None,
        )


def test_register_account_out_of_scope_blocks():
    with pytest.raises(PermissionError, match="out of scope"):
        register_account(
            signup_url="https://evil.com/signup",
            login_url="https://evil.com/login",
            program={"id": "test-p", "policy_text": "", "includes": ["example.com"], "excludes": []},
            mailbox=None,
        )


def test_register_account_flow_mock():
    mailbox_mock = MagicMock()
    mailbox_mock.email = "hunter1@1secmail.com"
    mailbox_mock.wait_for_link.return_value = "https://example.com/activate?code=xyz"

    def handler(req):
        if req.url.path == "/signup" and req.method == "GET":
            return httpx.Response(200, text='<input name="csrf_token" value="csrf123">')
        if req.url.path == "/signup" and req.method == "POST":
            return httpx.Response(200, text="Please check your email to activate.")
        if req.url.path == "/activate":
            return httpx.Response(200, text="Account activated successfully.")
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    prog = {"id": "test-p", "policy_text": "", "includes": ["example.com"], "excludes": []}

    acct = register_account(
        signup_url="https://example.com/signup",
        login_url="https://example.com/login",
        program=prog,
        mailbox=mailbox_mock,
        client=client,
        account_label="acct_a",
    )
    assert acct["user"] == "hunter1@1secmail.com"
    assert acct["id"] == "acct_a"
    assert "password" in acct


def test_register_account_captcha_flagged_for_manual():
    mailbox_mock = MagicMock()
    mailbox_mock.email = "hunter2@1secmail.com"

    def handler(req):
        if req.url.path == "/signup" and req.method == "GET":
            return httpx.Response(200, text='<div class="g-recaptcha" data-sitekey="6LcAbC"></div>'
                                            '<script src="https://www.google.com/recaptcha/api.js"></script>')
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    prog = {"id": "test-p", "policy_text": "", "includes": ["example.com"], "excludes": []}

    with pytest.raises(RegistrationError, match="CAPTCHA_REQUIRED"):
        register_account(
            signup_url="https://example.com/signup",
            login_url="https://example.com/login",
            program=prog,
            mailbox=mailbox_mock,
            client=client,
            account_label="acct_b",
        )


def test_register_account_js_required_flagged_for_manual():
    mailbox_mock = MagicMock()
    mailbox_mock.email = "hunter3@1secmail.com"

    def handler(req):
        if req.url.path == "/signup" and req.method == "GET":
            return httpx.Response(200, text='<html><body><div id="root"></div>'
                                            '<script src="/static/bundle.js"></script></body></html>')
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    prog = {"id": "test-p", "policy_text": "", "includes": ["example.com"], "excludes": []}

    with pytest.raises(RegistrationError, match="JS_REQUIRED"):
        register_account(
            signup_url="https://example.com/signup",
            login_url="https://example.com/login",
            program=prog,
            mailbox=mailbox_mock,
            client=client,
            account_label="acct_b",
        )
