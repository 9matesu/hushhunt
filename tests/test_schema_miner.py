import pytest

from hushhunt.schema_miner import parse_graphql_types, parse_openapi_paths


def test_parse_openapi_paths():
    openapi_spec = {
        "paths": {
            "/api/v1/users": {
                "get": {"summary": "list users"},
                "post": {
                    "parameters": [{"name": "role", "in": "query"}],
                    "requestBody": {"content": {"application/json": {"schema": {"properties": {"email": {}}}}}}
                }
            },
            "/api/v1/admin/purge": {
                "delete": {"summary": "purge data"}
            }
        }
    }

    endpoints = parse_openapi_paths(openapi_spec)
    assert len(endpoints) == 3
    paths = [e["path"] for e in endpoints]
    assert "/api/v1/users" in paths
    assert "/api/v1/admin/purge" in paths


def test_parse_graphql_types():
    introspection = {
        "data": {
            "__schema": {
                "types": [
                    {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}, {"name": "passwordHash"}]},
                    {"name": "Query", "kind": "OBJECT", "fields": [{"name": "getSensitiveData"}]}
                ]
            }
        }
    }

    fields = parse_graphql_types(introspection)
    assert "passwordHash" in fields
    assert "getSensitiveData" in fields
