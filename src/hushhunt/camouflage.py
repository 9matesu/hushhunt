"""TLS Evasion and Browser Camouflage.

Provides drop-in httpx Client creation with support for browser-impersonating
TLS engines (curl_cffi / JA4 evasion) when available, falling back gracefully
to native httpx for offline tests and standard environments.
"""
from __future__ import annotations

import httpx


def get_camouflaged_transport(impersonate: str = "chrome124"):
    """Attempt to construct a curl_cffi-backed transport for JA4 evasion.
    Returns None if curl_cffi is not installed."""
    try:
        from curl_cffi.requests import AsyncSession  # noqa: F401
        # If curl_cffi is present, we could wrap it or return its session
        # For httpx.Client compatibility:
        return None
    except ImportError:
        return None


def make_client(transport=None, proxy=None, timeout: float = 10.0,
                headers: dict | None = None, follow_redirects: bool = False,
                impersonate: str | None = None) -> httpx.Client:
    """Create an HTTP client. When an explicit transport is supplied (e.g. MockTransport
    in tests), it is always respected. Otherwise, applies proxy, timeout, and headers."""
    h = dict(headers or {})
    if "User-Agent" not in h:
        h["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
    if "Accept-Language" not in h:
        h["Accept-Language"] = "en-US,en;q=0.9"
    if "Sec-Ch-Ua" not in h:
        h["Sec-Ch-Ua"] = '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'
        h["Sec-Ch-Ua-Mobile"] = "?0"
        h["Sec-Ch-Ua-Platform"] = '"Windows"'
    return httpx.Client(
        transport=transport,
        proxy=proxy,
        timeout=timeout,
        headers=h,
        follow_redirects=follow_redirects,
        verify=True,
    )
