import re

import hushhunt.pipeline  # noqa: F401  (imports every check module)
from hushhunt.checks import CHECK_CATALOG
from hushhunt.checks.cwe import CWE_MAP


def test_every_catalog_check_has_a_cwe():
    assert CHECK_CATALOG, "catalog should be populated"
    for cid, defn in CHECK_CATALOG.items():
        assert cid in CWE_MAP, f"{cid} missing CWE"
        assert re.fullmatch(r"CWE-\d+", CWE_MAP[cid]), (cid, CWE_MAP[cid])


def test_known_mappings_are_right():
    assert CWE_MAP["xss_reflected"] == "CWE-79"
    assert CWE_MAP["idor"] == "CWE-639"
    assert CWE_MAP["cors_misconfig"] == "CWE-942"
    assert CWE_MAP["blind_oast"] == "CWE-918"
    assert CWE_MAP["cmd_inject"] == "CWE-77"
