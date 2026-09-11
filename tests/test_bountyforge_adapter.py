from unittest.mock import patch, MagicMock
import json
import pytest
from hushhunt.adapters.bountyforge import (
    find_bountyforge_dir,
    run_bountyforge_hunt,
    import_bountyforge_findings,
)


def test_find_bountyforge_dir():
    d = find_bountyforge_dir()
    assert d is not None
    assert (d / "tools" / "hunt.py").exists()


def test_run_bountyforge_hunt_scope_gate_blocks_out_of_scope():
    includes = ["example.com"]
    excludes = ["admin.example.com"]

    # Out of scope domain
    with pytest.raises(PermissionError, match="out of scope"):
        run_bountyforge_hunt(
            "https://evil.com/api",
            includes=includes,
            excludes=excludes,
        )

    # Excluded subdomain
    with pytest.raises(PermissionError, match="out of scope"):
        run_bountyforge_hunt(
            "https://admin.example.com/api",
            includes=includes,
            excludes=excludes,
        )


def test_run_bountyforge_hunt_executes_on_in_scope():
    includes = ["example.com"]
    excludes = []

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = json.dumps({
        "findings": [
            {
                "type": "IDOR",
                "endpoint": "/api/users/123",
                "severity": "high",
                "evidence": "User B accessed User A resource",
            }
        ]
    })

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        result = run_bountyforge_hunt(
            "https://example.com/api/users/123",
            includes=includes,
            excludes=excludes,
            idor_only=True,
        )
        assert len(result["findings"]) == 1
        assert result["findings"][0]["type"] == "IDOR"
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "--target" in cmd
        assert "--idor-only" in cmd


def test_import_bountyforge_findings_into_db():
    conn = MagicMock()
    findings = [
        {
            "type": "IDOR",
            "endpoint": "/api/users/123",
            "severity": "high",
            "evidence": "Observed cross-tenant leak",
        }
    ]
    imported = import_bountyforge_findings(
        conn,
        program_id="test-prog",
        target_url="https://example.com/api/users/123",
        findings=findings,
    )
    assert imported == 1
    conn.execute.assert_called()
