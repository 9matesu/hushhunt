from hushhunt.policy_lint import allowed_module, lint_policy

VULN_POLICY = """
# Program Policy
All *.smallco.io in scope.
Please do not run SQL injection timing based attacks — our DB is shared.
"""

CLEAN_POLICY = "Scope: app.smallco.io. Safe harbor applies."


def test_timing_rule_blocks_boolean_only():
    res = lint_policy(VULN_POLICY)
    assert "sqli_boolean" in res["blocked"]
    assert "xss_reflected" not in res["blocked"]
    assert len(res["flags"]) == 1
    assert "timing" in res["flags"][0][1].lower()


def test_dos_rule_blocks_blasters():
    res = lint_policy("Do not run any dos or stress testing.")
    assert {"sqli_boolean", "blind_oast", "graphql_probe"} <= res["blocked"]
    assert allowed_module(res["blocked"], "idor")


def test_no_account_registration_rule():
    res = lint_policy("You may not create accounts yourself.")
    assert {"idor", "mass_assign", "jwt_misuse"} <= res["blocked"]


def test_self_xss_ignore_blocks_persistence():
    res = lint_policy("We ignore self-XSS and stored XSS without a second victim.")
    assert "mass_assign" in res["blocked"]


def test_clean_policy_blocks_nothing():
    res = lint_policy(CLEAN_POLICY)
    assert res["blocked"] == set() and res["flags"] == []


def test_empty_policy_blocks_nothing():
    assert lint_policy("")["blocked"] == set()
    assert lint_policy(None)["blocked"] == set()
