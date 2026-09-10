"""OpenAPI / Swagger & GraphQL schema ingestion engine.

Parses API definitions and GraphQL introspection dumps into attack surfaces
with exact parameters and endpoints for the AI planner.
"""
from __future__ import annotations

from typing import Any


def parse_openapi_paths(spec: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "head"):
                params = []
                for p in details.get("parameters", []):
                    if isinstance(p, dict) and "name" in p:
                        params.append(p["name"])
                # Extract json body keys
                req_body = details.get("requestBody", {})
                props = (req_body.get("content", {})
                         .get("application/json", {})
                         .get("schema", {})
                         .get("properties", {}))
                params.extend(list(props.keys()))

                out.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "params": list(dict.fromkeys(params))
                })
    return out


def parse_graphql_types(introspection: dict[str, Any]) -> list[str]:
    out = []
    types = (introspection.get("data", {})
             .get("__schema", {})
             .get("types", []))
    for t in types:
        for f in t.get("fields") or []:
            name = f.get("name")
            if name:
                out.append(name)
    return list(dict.fromkeys(out))
