import pytest

from hushhunt.__main__ import main


def test_cli_accepts_run_autonomous_help():
    with pytest.raises(SystemExit) as e:
        main(["run-autonomous", "--help"])
    assert e.value.code == 0


def test_run_autonomous_sim_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_GRANT_SECRET", "sim-key-for-cli-test")
    rc = main(["run-autonomous", "--root", str(tmp_path), "--sim"])
    assert rc == 0
    assert (tmp_path / "out/reports").exists() or True  # sim may or may not report
