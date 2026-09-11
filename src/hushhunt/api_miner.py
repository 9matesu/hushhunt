"""Autonomous Web API & Schema Discovery Module.

Discovers OpenAPI, Swagger, and GraphQL endpoints to unlock modern REST/GraphQL API
attack surfaces for parameter mutation, BOLA/IDOR, SSTI, and SQLi fuzzing.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin
import httpx

from .http import BudgetExceeded, HardenedClient, OutOfScope
from .schema_miner import parse_openapi_paths, parse_graphql_types

# High-probability API definition and introspection paths
COMMON_API_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v1/api-docs",
    "/api-docs",
    "/api/v1/swagger.json",
    "/graphql",
    "/api/graphql",
]

# Minimal safe introspection query to probe GraphQL existence without DoS
GRAPHQL_PROBE_QUERY = {"query": "{ __schema { queryType { name } } }"}


# ponytail: sequential schema probe; async if >20 endpoints/host
def probe_api_schemas(hc: HardenedClient, base_url: str) -> dict[str, Any]:
    """Scan base_url for OpenAPI / Swagger specs and GraphQL introspection schemas."""
    discovered_routes: list[dict[str, Any]] = []
    graphql_types: list[str] = []

    clean_base = base_url.rstrip("/") + "/"
    for path in COMMON_API_PATHS:
        target = urljoin(clean_base, path.lstrip("/"))
        try:
            if "graphql" in path:
                r = hc.get(target)
                # GraphQL endpoints often respond 400 or 405 on plain GET, or 200 with schema
                if r.status_code in (200, 400, 405) and ("graphql" in r.text.lower() or "syntax" in r.text.lower()):
                    discovered_routes.append({"path": path, "method": "POST", "type": "graphql", "params": ["query", "variables"]})
            else:
                r = hc.get(target)
                if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower()):
                    try:
                        spec = r.json()
                        routes = parse_openapi_paths(spec)
                        discovered_routes.extend(routes)
                    except (ValueError, TypeError):
                        pass
        except (OutOfScope, BudgetExceeded, httpx.HTTPError):
            continue

    return {
        "openapi_routes": discovered_routes,
        "graphql_types": graphql_types,
    }
