from hushhunt.scope import url_in_scope

INC = ["*.smallco.io", "app.smallco.io"]
EXC = ["blog.smallco.io"]


def test_wildcard_matches_sub_and_apex():
    assert url_in_scope("https://api.smallco.io/x", INC, EXC)
    assert url_in_scope("https://smallco.io/", INC, EXC)
    assert url_in_scope("https://deep.sub.smallco.io/", INC, EXC)


def test_lookalike_rejected():
    assert not url_in_scope("https://notexample.com", ["*.example.com"], [])
    assert not url_in_scope("https://smallco.io.attacker.net", INC, EXC)


def test_exclusion_wins_over_wildcard():
    assert not url_in_scope("https://blog.smallco.io", INC, EXC)
    assert not url_in_scope("https://sub.blog.smallco.io", INC, EXC)


def test_exact_domain_from_identifier():
    assert url_in_scope("https://app.smallco.io/login", INC, EXC)


def test_default_deny():
    assert not url_in_scope("https://anything.io", [], [])


def test_non_http_schemes_denied():
    assert not url_in_scope("file:///etc/passwd", INC, EXC)
    assert not url_in_scope("gopher://smallco.io:11211/", INC, EXC)


def test_leading_dot_identifier():
    assert url_in_scope("https://a.example.org", [".example.org"], [])


def test_uppercase_host_normalized():
    assert url_in_scope("https://API.SMALLCO.IO/x", INC, EXC)
