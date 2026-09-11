from __future__ import annotations

import os
import re
import secrets
import string
from pathlib import Path
from urllib.parse import urlparse
from typing import Any
import httpx

from .scope import url_in_scope
from .policy_lint import lint_policy
from .mail_pool import DisposableMailbox

CSRF_PATTERN = re.compile(
    r'<input[^>]+name=[\'"](csrf_token|authenticity_token|_csrf|_token|csrf)[\'"][^>]+value=[\'"]([^\'"]+)[\'"]',
    re.I
)


class RegistrationError(Exception):
    pass


def generate_secure_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def register_account(
    signup_url: str,
    login_url: str,
    program: dict[str, Any],
    mailbox: DisposableMailbox | None = None,
    client: httpx.Client | None = None,
    account_label: str = "acct_a",
    user_field: str = "email",
    password_field: str = "password",
) -> dict[str, Any]:
    """Execute automated registration flow strictly within scope and program policy."""
    includes = program.get("includes", [])
    excludes = program.get("excludes", [])

    # Scope verification
    if not url_in_scope(signup_url, includes, excludes):
        raise PermissionError(f"Signup URL {signup_url} is out of scope.")
    if not url_in_scope(login_url, includes, excludes):
        raise PermissionError(f"Login URL {login_url} is out of scope.")

    # Policy linting gate
    policy = program.get("policy_text", "")
    lint_result = lint_policy(policy)
    if any("account" in flag[1].lower() or "regist" in flag[1].lower() for flag in lint_result.get("flags", [])):
        raise PermissionError("Registration forbidden by program policy rules.")

    http = client or httpx.Client(timeout=20.0, follow_redirects=True)
    box = mailbox or DisposableMailbox(client=http)

    password = generate_secure_password()
    email = box.email

    # 1. Fetch signup form & extract CSRF
    get_resp = http.get(signup_url)
    get_resp.raise_for_status()

    csrf_match = CSRF_PATTERN.search(get_resp.text)
    csrf_name, csrf_val = (csrf_match.group(1), csrf_match.group(2)) if csrf_match else (None, None)

    post_data = {user_field: email, password_field: password}
    if csrf_name and csrf_val:
        post_data[csrf_name] = csrf_val

    # 2. Submit signup form
    post_resp = http.post(signup_url, data=post_data)
    if post_resp.status_code >= 400:
        raise RegistrationError(f"Signup POST failed: HTTP {post_resp.status_code}")

    # 3. Poll for activation link
    allowed_hosts = [urlparse(signup_url).hostname or ""]
    activation_url = box.wait_for_link(allowed_hosts=allowed_hosts, timeout=60, interval=3)

    if activation_url:
        if not url_in_scope(activation_url, includes, excludes):
            raise PermissionError(f"Activation URL {activation_url} is out of scope.")
        act_resp = http.get(activation_url)
        if act_resp.status_code >= 400:
            raise RegistrationError(f"Activation GET failed: HTTP {act_resp.status_code}")

    return {
        "id": account_label,
        "user": email,
        "password": password,
        "login_url": login_url,
        "signup_url": signup_url,
        "csrf_field": csrf_name,
    }


def save_program_accounts(
    accounts_path: Path,
    program_id: str,
    accounts: list[dict[str, Any]],
) -> None:
    """Save account configs to accounts.yaml with passwords exported to ENV only."""
    import yaml
    data = {}
    if accounts_path.exists():
        data = yaml.safe_load(accounts_path.read_text(encoding="utf-8")) or {}

    sanitized_pid = re.sub(r'[^A-Za-z0-9_]', '_', program_id).upper()
    stored_list = []

    for acct in accounts:
        aid = acct["id"]
        env_var = f"HH_PASS_{sanitized_pid}_{aid.upper()}"
        os.environ[env_var] = acct["password"]

        entry = {
            "id": aid,
            "user": acct["user"],
            "password_env": env_var,
            "login_url": acct["login_url"],
        }
        if acct.get("csrf_field"):
            entry["csrf_field"] = acct["csrf_field"]
        stored_list.append(entry)

    data[program_id] = stored_list
    accounts_path.parent.mkdir(parents=True, exist_ok=True)
    accounts_path.write_text(yaml.dump(data, sort_keys=False), encoding="utf-8")
