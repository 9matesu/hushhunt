from unittest.mock import MagicMock
import httpx
import pytest
from hushhunt.mail_pool import DisposableMailbox, extract_activation_link


def test_extract_activation_link():
    html_body = '<p>Welcome! Click <a href="https://example.com/verify?token=abc123xyz">here</a> to verify.</p>'
    link = extract_activation_link(html_body, allowed_hosts=["example.com"])
    assert link == "https://example.com/verify?token=abc123xyz"

    # Out of scope host ignored
    bad_body = '<p>Click <a href="https://phishing.com/steal">here</a></p>'
    assert extract_activation_link(bad_body, allowed_hosts=["example.com"]) is None


def test_mailbox_create_and_poll_mock():
    def handler(req):
        url_str = str(req.url)
        if "action=genRandomMailbox" in url_str:
            return httpx.Response(200, json=["testuser@1secmail.com"])
        if "action=getMessages" in url_str:
            return httpx.Response(200, json=[{"id": 42, "from": "no-reply@example.com", "subject": "Verify account"}])
        if "action=readMessage" in url_str:
            return httpx.Response(200, json={"body": '<a href="https://example.com/verify?token=tok">Verify</a>'})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    box = DisposableMailbox(client=client)
    assert box.email == "testuser@1secmail.com"
    msgs = box.check_messages()
    assert len(msgs) == 1
    content = box.read_message(42)
    link = extract_activation_link(content["body"], allowed_hosts=["example.com"])
    assert link == "https://example.com/verify?token=tok"


def test_mailbox_fallback_to_alternate_provider():
    def handler(req):
        url_str = str(req.url)
        # Primary provider 1secmail fails with 500
        if "1secmail.com" in url_str:
            return httpx.Response(500)
        # Alternate provider endpoints
        if "f=get_email_address" in url_str:
            return httpx.Response(200, json={"email_addr": "altuser@guerrillamail.com", "sid_token": "token123"})
        if "f=check_email" in url_str:
            return httpx.Response(200, json={"list": [{"mail_id": 99, "mail_subject": "Confirm"}]})
        if "f=fetch_email" in url_str:
            return httpx.Response(200, json={"mail_body": '<a href="https://example.com/verify?alt=1">Link</a>'})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    box = DisposableMailbox(client=client)
    assert box.email == "altuser@guerrillamail.com"
    msgs = box.check_messages()
    assert len(msgs) == 1
    link = box.wait_for_link(allowed_hosts=["example.com"], timeout=1)
    assert link == "https://example.com/verify?alt=1"
