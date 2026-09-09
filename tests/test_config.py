from hushhunt.config import Config


def test_load_nested_and_defaults(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "llm:\n  base_url: http://x/v1\nlimits:\n  daily_requests_per_program: 10\n")
    cfg = Config.load(tmp_path)
    assert cfg["llm.base_url"] == "http://x/v1"
    assert cfg["limits.daily_requests_per_program"] == 10


def test_secret_missing_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("HH_NOPE", raising=False)
    cfg = Config({"llm": {}}, tmp_path)
    try:
        cfg.secret("HH_NOPE")
        assert False, "should raise"
    except RuntimeError as e:
        assert "HH_NOPE" in str(e)


def test_secret_found(tmp_path, monkeypatch):
    monkeypatch.setenv("HH_TEST_SECRET", "s3cr3t")
    cfg = Config({"llm": {}}, tmp_path)
    assert cfg.secret("HH_TEST_SECRET") == "s3cr3t"
