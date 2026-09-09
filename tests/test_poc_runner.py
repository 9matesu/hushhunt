import ast
import json

import httpx
import pytest

from hushhunt.poc import PoCContractError, run_poc, synthesize_poc, validate_ast
from tests.vulnapp import handler
from hushhunt.checks import Ctx
import hushhunt.checks.active.xss  # noqa: F401  (registers)

GOOD_POC = """
r = client.fetch("https://t.invalid/search?q=%3Cb%3Ehush%3C%2Fb%3E")
assert r.status_code == 200
assert "<b>hush</b>" in r.text
result["ok"] = True
"""

EVIL_POC_IMPORT = "import os\nresult['ok'] = True"
EVIL_POC_OPEN = "open('C:/windows/win.ini')\nresult['ok'] = True"
EVIL_POC_EXEC = "exec('result[1]=1')\nresult['ok'] = True"
EVIL_POC_DUNDER = "x = ().__class__\nresult['ok'] = True"
FAILING_POC = 'r = client.fetch("https://t.invalid/nowhere")\nassert False'


def _client():
    class C:
        def __init__(self):
            self.n = 0
        def fetch(self, url, headers=None):
            self.n += 1
            return httpx.Client(transport=httpx.MockTransport(handler)).get(url)
    return C()


def test_good_poc_passes_sandbox_and_proves():
    c = _client()
    assert run_poc(GOOD_POC, c) is True
    assert c.n == 1


def test_import_rejected_zero_execution(tmp_path):
    c = _client()
    with pytest.raises(PoCContractError):
        run_poc(EVIL_POC_IMPORT, c)
    assert c.n == 0


def test_open_rejected():
    with pytest.raises(PoCContractError):
        run_poc(EVIL_POC_OPEN, _client())


def test_exec_rejected():
    with pytest.raises(PoCContractError):
        run_poc(EVIL_POC_EXEC, _client())


def test_dunder_walk_rejected():
    with pytest.raises(PoCContractError):
        run_poc(EVIL_POC_DUNDER, _client())


def test_assertion_failure_returns_false_not_crash():
    assert run_poc(FAILING_POC, _client()) is False


def test_validate_ast_accepts_plain_arithmetic():
    validate_ast("x = 7 * 7\nassert x == 49")


def test_syntax_error_is_contract_error():
    with pytest.raises(PoCContractError):
        validate_ast("def (")


class FakeLlm:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete_json(self, system, user):
        self.calls.append((system, user))
        return self.reply


def test_synthesize_poc_extracts_script():
    llm = FakeLlm({"poc_script": GOOD_POC})
    cfg = type("C", (), {"root": __import__("pathlib").Path(".")})()
    finding = {"id": 3, "detail_json": json.dumps(
        {"title": "reflected xss", "impact": "x", "cvss": "CVSS:3.1/..."})}
    sig = {"check_id": "xss_reflected", "asset": "https://t.invalid/search?q=x",
           "payload_json": '{"param":"q","marker":"hush"}', "evidence_dir": "",
           "wstg": "WSTG-INPV-01"}
    code = synthesize_poc(cfg, llm, finding, [sig])
    assert code and "client.fetch" in code
    assert "search" in llm.calls[0][1]        # evidence was in the prompt


def test_synthesize_rejects_evil_script_from_llm():
    llm = FakeLlm({"poc_script": EVIL_POC_IMPORT})
    finding = {"id": 3, "detail_json": "{}"}
    with pytest.raises(PoCContractError):
        synthesize_poc(None, llm, finding,
                       [{"check_id": "xss_reflected", "asset": "a",
                         "payload_json": "{}", "evidence_dir": "", "wstg": "w"}])
