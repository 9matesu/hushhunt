import json
import httpx
import pytest

from hushhunt.api_miner import probe_api_schemas
from hushhunt.config import Config
from hushhunt.db import open_db, upsert_program
from hushhunt.http import HardenedClient

LIMITS = {
    "limits": {
        "rate_per_second_per_target": 10000,
        "daily_requests_per_program": 100,
        "max_requests_per_asset": 100,
        "request_timeout_seconds": 5,
        "user_agent": "t",
    }
}

PROG = {
    "id": "h1:api_test",
    "name": "API Test",
    "includes": ["api.target.invalid"],
    "excludes": [],
    "safe_harbor": "all",
}


def test_probe_api_schemas_discovers_swagger(tmp_path):
    conn = open_db(tmp_path / "t.db")
    upsert_program(conn, {"id": "h1:api_test", "platform": "h1", "name": "API Test",
                          "url": "http://x", "safe_harbor": "all", "max_bounty": 1000,
                          "avg_resolution_h": 0, "created_at_remote": None, "policy_text": "",
                          "scope_json": json.dumps({"includes": ["api.target.invalid"], "excludes": []})})

    openapi_doc = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/users": {
                "get": {
                    "parameters": [{"name": "role", "in": "query"}]
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "username": {"type": "string"},
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    def handler(req: httpx.Request):
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json=openapi_doc)
        return httpx.Response(404, text="Not Found")

    hc = HardenedClient(conn, Config(LIMITS, tmp_path), PROG, transport=httpx.MockTransport(handler))
    results = probe_api_schemas(hc, "https://api.target.invalid/")
    routes = results["openapi_routes"]
    assert len(routes) >= 2
    paths = {r["path"] for r in routes}
    assert "/api/v1/users" in paths
    all_params = [p for r in routes for p in r.get("params", [])]
    assert "role" in all_params
    assert "username" in all_params
    assert "email" in all_params
