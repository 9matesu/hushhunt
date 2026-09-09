from pathlib import Path

from hushhunt.config import Config
from hushhunt.operator import ask, drain_steer


def test_ask_writes_structured_question(tmp_path):
    cfg = Config({"triage": {}}, tmp_path)
    ask(cfg, {"id": "h1:1"}, "no_test_accounts",
        "idor granted but seeds/accounts.yaml missing acct entries",
        ["register accounts", "revoke idor grant"])
    body = (tmp_path / "out/QUESTIONS.md").read_text(encoding="utf-8")
    assert "h1:1 — no_test_accounts" in body
    assert "register accounts | revoke idor grant" in body


def test_drain_steer_one_shot(tmp_path):
    (tmp_path / "var").mkdir()
    (tmp_path / "var/steer.txt").write_text(
        "skip:h1:2\nfocus auth surface harder\n", encoding="utf-8")
    cfg = Config({}, tmp_path)
    r = drain_steer(cfg)
    assert r["skip"] == {"h1:2"}
    assert r["focus"] == ["focus auth surface harder"]
    assert r["stop"] is False
    # drained: second read is empty
    assert drain_steer(cfg) == {"stop": False, "skip": set(), "focus": []}


def test_stop_line(tmp_path):
    (tmp_path / "var").mkdir()
    (tmp_path / "var/steer.txt").write_text("STOP\n", encoding="utf-8")
    cfg = Config({}, tmp_path)
    assert drain_steer(cfg)["stop"] is True
