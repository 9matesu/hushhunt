from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# ponytail: stdlib-only CIS config parsers; add live WMI/GPO live registry queries when deployed on DCs.
WEAK_SSH_CIPHERS = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "blowfish-cbc", "cast128-cbc"}


def audit_sshd_config(config_text: str) -> list[dict[str, Any]]:
    """Audit OpenSSH daemon configuration against CIS / security baselines."""
    findings: list[dict[str, Any]] = []
    lines = [line.strip() for line in config_text.splitlines() if line.strip() and not line.strip().startswith("#")]
    settings: dict[str, str] = {}
    for line in lines:
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, val = parts[0].lower(), parts[1].strip()
            settings[key] = val

    if settings.get("permitrootlogin", "").lower() in ("yes", "without-password"):
        findings.append({
            "id": "ssh:permit_root_login",
            "severity": "high",
            "issue": f"PermitRootLogin set to '{settings['permitrootlogin']}', root login should be disabled."
        })

    if settings.get("passwordauthentication", "").lower() == "yes":
        findings.append({
            "id": "ssh:password_auth_enabled",
            "severity": "medium",
            "issue": "PasswordAuthentication is enabled; key-based authentication preferred."
        })

    try:
        max_tries = int(settings.get("maxauthtries", "6"))
        if max_tries > 4:
            findings.append({
                "id": "ssh:max_auth_tries_high",
                "severity": "low",
                "issue": f"MaxAuthTries is {max_tries} (recommended <= 4 to mitigate brute-force)."
            })
    except ValueError:
        pass

    ciphers = [c.strip().lower() for c in settings.get("ciphers", "").split(",")]
    weak_found = [c for c in ciphers if c in WEAK_SSH_CIPHERS]
    if weak_found:
        findings.append({
            "id": "ssh:weak_ciphers",
            "severity": "high",
            "issue": f"Weak or legacy ciphers configured: {', '.join(weak_found)}."
        })

    return findings


def audit_ad_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Audit Active Directory domain security settings against MS security baseline."""
    findings: list[dict[str, Any]] = []

    min_pwd_len = int(policy.get("MinimumPasswordLength", 0))
    if min_pwd_len < 14:
        findings.append({
            "id": "ad:short_password_length",
            "severity": "high",
            "issue": f"Minimum password length is {min_pwd_len} (recommended >= 14)."
        })

    if int(policy.get("PasswordComplexity", 0)) == 0:
        findings.append({
            "id": "ad:no_password_complexity",
            "severity": "medium",
            "issue": "Password complexity requirements are disabled."
        })

    lockout_thresh = int(policy.get("LockoutBadCount", 0))
    if lockout_thresh == 0 or lockout_thresh > 10:
        findings.append({
            "id": "ad:no_lockout_threshold",
            "severity": "medium",
            "issue": f"Account lockout threshold is {lockout_thresh} (recommended 3-5)."
        })

    ldap_integrity = int(policy.get("LDAPServerIntegrity", 1))
    if ldap_integrity < 2:
        findings.append({
            "id": "ad:missing_ldap_signing",
            "severity": "high",
            "issue": "LDAP server signing not enforced (LDAPServerIntegrity < 2), vulnerable to NTLM relay."
        })

    lm_level = int(policy.get("LmCompatibilityLevel", 0))
    if lm_level < 5:
        findings.append({
            "id": "ad:ntlmv1_enabled",
            "severity": "high",
            "issue": f"LmCompatibilityLevel is {lm_level}; NTLMv1 or LM accepted (recommended 5: NTLMv2 only)."
        })

    quota = int(policy.get("MachineAccountQuota", 10))
    if quota > 0:
        findings.append({
            "id": "ad:machine_account_quota_nonzero",
            "severity": "medium",
            "issue": f"ms-DS-MachineAccountQuota is {quota}; unprivileged users can join computers."
        })

    return findings
