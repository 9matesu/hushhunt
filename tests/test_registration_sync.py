import yaml
from hushhunt.registration import save_program_accounts


def test_save_program_accounts(tmp_path, monkeypatch):
    accounts_file = tmp_path / "seeds" / "accounts.yaml"
    accounts_file.parent.mkdir()
    accounts_file.write_text("{}", encoding="utf-8")

    acct_a = {"id": "acct_a", "user": "a@mail.com", "password": "passA123!", "login_url": "https://target.com/login", "csrf_field": None}
    acct_b = {"id": "acct_b", "user": "b@mail.com", "password": "passB456!", "login_url": "https://target.com/login", "csrf_field": "csrf"}

    save_program_accounts(
        accounts_path=accounts_file,
        program_id="h1:target-prog",
        accounts=[acct_a, acct_b],
    )

    data = yaml.safe_load(accounts_file.read_text(encoding="utf-8"))
    assert "h1:target-prog" in data
    assert len(data["h1:target-prog"]) == 2
    assert data["h1:target-prog"][0]["id"] == "acct_a"
    assert data["h1:target-prog"][0]["password_env"] == "HH_PASS_H1_TARGET_PROG_ACCT_A"
    assert "password" not in data["h1:target-prog"][0]

    import os
    assert os.environ.get("HH_PASS_H1_TARGET_PROG_ACCT_A") == "passA123!"
