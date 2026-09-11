from __future__ import annotations

import os
import re
import time
from typing import Any
import httpx

# ponytail: 2captcha/anticaptcha compatible standard wire protocol
SOLVER_BASE = "https://2captcha.com"

RECAPTCHA_RE = re.compile(r'class=[\'"][^\'"]*g-recaptcha[^\'"]*[\'"][^>]*data-sitekey=[\'"]([^\'"]+)[\'"]|data-sitekey=[\'"]([^\'"]+)[\'"][^>]*class=[\'"][^\'"]*g-recaptcha', re.I)
TURNSTILE_RE = re.compile(r'class=[\'"][^\'"]*cf-turnstile[^\'"]*[\'"][^>]*data-sitekey=[\'"]([^\'"]+)[\'"]|challenges\.cloudflare\.com/turnstile/v0/api\.js', re.I)
HCAPTCHA_RE = re.compile(r'class=[\'"][^\'"]*h-captcha[^\'"]*[\'"][^>]*data-sitekey=[\'"]([^\'"]+)[\'"]', re.I)
GENERIC_SITEKEY_RE = re.compile(r'data-sitekey=[\'"]([^\'"]+)[\'"]', re.I)


def extract_sitekey(html: str) -> tuple[str | None, str | None]:
    """Detect presence and extract sitekey for reCAPTCHA, Turnstile, or hCaptcha."""
    m_re = RECAPTCHA_RE.search(html)
    if m_re:
        key = m_re.group(1) or m_re.group(2)
        return key, "recaptcha"

    m_turn = TURNSTILE_RE.search(html)
    if m_turn:
        key = m_turn.group(1) if m_turn.lastindex else None
        if not key:
            gen = GENERIC_SITEKEY_RE.search(html)
            key = gen.group(1) if gen else None
        return key, "turnstile"

    m_h = HCAPTCHA_RE.search(html)
    if m_h:
        return m_h.group(1), "hcaptcha"

    gen = GENERIC_SITEKEY_RE.search(html)
    if gen:
        return gen.group(1), "generic"

    return None, None


def solve_captcha(
    page_url: str,
    sitekey: str,
    captcha_type: str = "recaptcha",
    api_key: str | None = None,
    client: httpx.Client | None = None,
    timeout: int = 60,
    poll_interval: float = 3.0,
) -> str:
    """Submit captcha solve request to solver service and poll for token."""
    key = api_key or os.environ.get("HH_CAPTCHA_API_KEY")
    if not key:
        raise RuntimeError("CAPTCHA solver requires HH_CAPTCHA_API_KEY environment variable")

    http = client or httpx.Client(timeout=15.0)
    method_map = {
        "recaptcha": "userrecaptcha",
        "turnstile": "turnstile",
        "hcaptcha": "hcaptcha",
    }
    method = method_map.get(captcha_type, "userrecaptcha")

    # 1. Create task
    in_resp = http.post(
        f"{SOLVER_BASE}/in.php",
        data={
            "key": key,
            "method": method,
            "googlekey": sitekey,
            "pageurl": page_url,
            "json": 0,
        },
    )
    in_text = in_resp.text.strip()
    if not in_text.startswith("OK|"):
        raise RuntimeError(f"Solver in.php rejected task: {in_text}")

    task_id = in_text.split("|")[1]

    # 2. Poll for token
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll_interval)
        res = http.get(
            f"{SOLVER_BASE}/res.php",
            params={"key": key, "action": "get", "id": task_id},
        )
        res_text = res.text.strip()
        if res_text == "CAPCHA_NOT_READY":
            continue
        if res_text.startswith("OK|"):
            return res_text.split("|")[1]
        raise RuntimeError(f"Solver res.php returned error: {res_text}")

    raise TimeoutError(f"CAPTCHA solver timed out after {timeout}s")
