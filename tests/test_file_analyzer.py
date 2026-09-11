from pathlib import Path
from hushhunt.checks.file_analyzer import scan_file_content, scan_directory


def test_detects_private_key_and_ad_string():
    raw = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA...\n-----END OPENSSH PRIVATE KEY-----\n"
        "connection = 'LDAP://dc01.corp.internal:389/DC=corp,DC=internal'\n"
        "api_key = 'AKIAIOSFODNN7EXAMPLE'\n"
    )
    hits = scan_file_content(raw, "config.py")
    checks = {h["check_id"] for h in hits}
    assert "secret:private_key" in checks
    assert "secret:ad_connection_string" in checks
    assert "secret:aws_access_key" in checks
    assert len(hits) == 3


def test_scan_directory_walks_and_skips_git(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / ".git").mkdir()
    (tmp_path / "app" / "settings.env").write_text("DB_PASSWORD='supersecretpassword123'\n")
    (tmp_path / ".git" / "dummy").write_text("password='dontscanthis'\n")
    hits = scan_directory(tmp_path)
    assert len(hits) == 1
    assert "password_assignment" in hits[0]["check_id"]
