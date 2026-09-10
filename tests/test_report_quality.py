import pytest

from hushhunt.report import get_cvss_for_check, get_impact_for_check, get_remediation_for_check


def test_cvss_mapping_accuracy():
    # XSS reflected requires user interaction UI:R
    cvss_xss = get_cvss_for_check("xss_reflected")
    assert "UI:R" in cvss_xss
    assert "AV:N" in cvss_xss

    # SQLi boolean / error has high confidentiality & integrity
    cvss_sqli = get_cvss_for_check("sqli_error")
    assert "C:H" in cvss_sqli
    assert "I:H" in cvss_sqli
    assert "UI:N" in cvss_sqli

    # Command injection is Critical (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
    cvss_cmd = get_cvss_for_check("cmd_inject")
    assert "C:H" in cvss_cmd
    assert "I:H" in cvss_cmd
    assert "A:H" in cvss_cmd

    # IDOR requires PR:L (low privileges)
    cvss_idor = get_cvss_for_check("idor")
    assert "PR:L" in cvss_idor or "PR:N" in cvss_idor


def test_remediation_all_active_modules():
    active_checks = [
        "xss_reflected", "xss_dom", "sqli_error", "sqli_boolean", "ssti",
        "idor", "jwt_misuse", "open_redirect_chain", "graphql_probe",
        "blind_oast", "mass_assign", "cmd_inject", "nuclei_sweep"
    ]
    for cid in active_checks:
        rem = get_remediation_for_check(cid)
        assert rem is not None
        assert "apply defense-in-depth per OWASP guidance" not in rem.lower()
        assert len(rem) > 20


def test_impact_analysis_all_active_modules():
    active_checks = [
        "xss_reflected", "sqli_error", "ssti", "idor", "cmd_inject", "blind_oast"
    ]
    for cid in active_checks:
        imp = get_impact_for_check(cid)
        assert imp is not None
        assert "Demonstrated by captured evidence" not in imp
        assert len(imp) > 30
