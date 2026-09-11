from unittest.mock import patch
import socket
import httpx
from hushhunt.checks import Ctx
from hushhunt.checks.exposed_services import check_exposed_services


def test_exposed_services_flags_open_ports():
    resp = httpx.Response(200, request=httpx.Request("GET", "https://target.corp.com/"))
    ctx = Ctx(resp=resp, asset_url="https://target.corp.com/")

    def fake_create_connection(addr, timeout=None):
        host, port = addr
        if port == 22:
            s = socket.socket()
            return s
        raise ConnectionRefusedError("port closed")

    with patch("socket.create_connection", side_effect=fake_create_connection):
        signals = check_exposed_services(ctx)
        assert len(signals) == 1
        assert signals[0]["check_id"] == "exposed_services"
        assert signals[0]["payload"]["port"] == 22
        assert signals[0]["payload"]["service"] == "ssh"


def test_exposed_services_returns_empty_when_all_closed():
    resp = httpx.Response(200, request=httpx.Request("GET", "https://target.corp.com/"))
    ctx = Ctx(resp=resp, asset_url="https://target.corp.com/")

    def fake_create_connection(addr, timeout=None):
        raise socket.timeout("timed out")

    with patch("socket.create_connection", side_effect=fake_create_connection):
        signals = check_exposed_services(ctx)
        assert signals == []
