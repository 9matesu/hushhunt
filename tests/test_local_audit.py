from pathlib import Path
from hushhunt.local_audit import audit_sshd_config, audit_ad_policy

def test_audit_sshd_config_flags_insecure():
    insecure_sshd = """
    PermitRootLogin yes
    PasswordAuthentication yes
    MaxAuthTries 10
    X11Forwarding yes
    Ciphers aes128-cbc,3des-cbc
    """
    findings = audit_sshd_config(insecure_sshd)
    checks = {f["id"] for f in findings}
    assert "ssh:permit_root_login" in checks
    assert "ssh:password_auth_enabled" in checks
    assert "ssh:max_auth_tries_high" in checks
    assert "ssh:weak_ciphers" in checks

def test_audit_sshd_config_passes_hardened():
    hardened_sshd = """
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    MaxAuthTries 3
    X11Forwarding no
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    """
    findings = audit_sshd_config(hardened_sshd)
    assert len(findings) == 0

def test_audit_ad_policy_flags_weaknesses():
    policy = {
        "MinimumPasswordLength": 8,
        "PasswordComplexity": 0,
        "LockoutBadCount": 0,
        "LDAPServerIntegrity": 1,
        "LmCompatibilityLevel": 1,
        "MachineAccountQuota": 10
    }
    findings = audit_ad_policy(policy)
    checks = {f["id"] for f in findings}
    assert "ad:short_password_length" in checks
    assert "ad:no_password_complexity" in checks
    assert "ad:no_lockout_threshold" in checks
    assert "ad:missing_ldap_signing" in checks
    assert "ad:ntlmv1_enabled" in checks
    assert "ad:machine_account_quota_nonzero" in checks

def test_audit_ad_policy_passes_hardened():
    hardened_policy = {
        "MinimumPasswordLength": 15,
        "PasswordComplexity": 1,
        "LockoutBadCount": 5,
        "LDAPServerIntegrity": 2,
        "LmCompatibilityLevel": 5,
        "MachineAccountQuota": 0
    }
    findings = audit_ad_policy(hardened_policy)
    assert len(findings) == 0
