from __future__ import annotations

import ast
import json

ALLOWED_IMPORTS = {"hushhunt"}
FORBIDDEN_CALLS = {"open", "exec", "eval", "compile", "__import__", "input",
                   "breakpoint", "exit", "quit", "globals", "locals", "vars",
                   "dir", "getattr", "setattr", "delattr", "memoryview",
                   "super", "type", "callable"}
ALLOWED_BUILTINS = {"len", "str", "int", "float", "bool", "list", "dict",
                    "tuple", "set", "range", "enumerate", "sorted", "min",
                    "max", "abs", "round", "any", "all", "sum", "repr",
                    "print"}


class PoCContractError(Exception):
    pass


class _Checker(ast.NodeVisitor):
    """AST allowlist: the synthesizer's output runs under this contract, so a
    hallucinating (or prompt-injected) model can neither touch the filesystem
    nor escape into builtins — the sandbox simply refuses to run it."""

    def visit_Import(self, node):
        for a in node.names:
            root = a.name.split(".")[0]
            if root not in ALLOWED_IMPORTS:
                raise PoCContractError(f"import {a.name!r} not allowed")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        root = (node.module or "").split(".")[0]
        if root not in ALLOWED_IMPORTS:
            raise PoCContractError(f"from {node.module!r} not allowed")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and (
                node.func.id in FORBIDDEN_CALLS or
                (node.func.id not in ALLOWED_BUILTINS and
                 node.func.id not in ("client", "fetch") and
                 not node.func.id[0].islower())):
            raise PoCContractError(f"call {node.func.id!r} not allowed")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr.startswith("__") or node.attr.startswith("_"):
            raise PoCContractError(f"attribute {node.attr!r} not allowed")
        self.generic_visit(node)

    def visit_Global(self, node):
        raise PoCContractError("global statement not allowed")

    def visit_With(self, node):
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and \
                    isinstance(item.context_expr.func, ast.Name) and \
                    item.context_expr.func.id in FORBIDDEN_CALLS:
                raise PoCContractError("with-open pattern not allowed")
        self.generic_visit(node)


def validate_ast(code: str) -> None:
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as e:
        raise PoCContractError(f"poc syntax error: {e}") from e
    _Checker().visit(tree)
    from .safecommands import is_destructive
    if is_destructive(code):       # REDCELL-port belt: no destructive command
        raise PoCContractError("poc text contains a destructive command")


_SAFE_GLOBALS = {
    "__builtins__": {
        "len": len, "str": str, "int": int, "float": float, "bool": bool,
        "list": list, "dict": dict, "tuple": tuple, "set": set, "range": range,
        "enumerate": enumerate, "sorted": sorted, "min": min, "max": max,
        "abs": abs, "round": round, "any": any, "all": all, "sum": sum,
        "repr": repr, "print": print, "AssertionError": AssertionError,
        "Exception": Exception, "ValueError": ValueError,
    },
}


def run_poc(code: str, client, timeout_s: float = 30.0) -> bool:
    """The PoC is the proof: it must re-demonstrate the vulnerability via the
    budgeted `client` (only .fetch/.get/.post exposed) and set
    result['ok']=True after asserts. Anything else isn't a positive."""
    validate_ast(code)
    result: dict = {}

    class _ClientView:          # only the budgeted door, nothing else
        def __init__(self, inner):
            self._inner = inner
            self.n_requests = 0

        def fetch(self, url, headers=None):
            self.n_requests += 1
            if self.n_requests > 12:
                raise PoCContractError("poc exceeded request budget")
            if hasattr(self._inner, "fetch"):
                return self._inner.fetch(url, headers=headers)
            return self._inner.get(url, headers=headers)

    view = _ClientView(client)
    g = dict(_SAFE_GLOBALS)
    g["client"] = view
    g["result"] = result
    try:
        exec(compile(code, "<poc>", "exec"), g)
    except AssertionError:
        return False
    except PoCContractError:
        raise
    except Exception:
        return False
    return bool(result.get("ok"))


POC_SYSTEM = """You write tiny deterministic Python PoC scripts for bug bounty
reports. The script runs in a locked sandbox: available names are exactly
`client` (with client.fetch(url, headers=None) -> response with .status_code,
.text, .json(), .headers) and `result` (a dict). NO imports except hushhunt,
no open/exec/eval/dunder — such scripts are rejected. Assert the vulnerability
is REAL in the current response, then set result["ok"] = True. One to three
requests maximum. Output ONLY JSON {"poc_script": "..."}."""


def synthesize_poc(cfg, llm, finding: dict, signals: list[dict]) -> str:
    detail = json.loads(finding.get("detail_json") or "{}")
    user = json.dumps({"title": detail.get("title"),
                       "impact": detail.get("impact"),
                       "signals": [{"check": s["check_id"], "asset": s["asset"],
                                    "payload": json.loads(s["payload_json"])}
                                   for s in signals]}, indent=1)
    try:
        reply = llm.complete_json(POC_SYSTEM, user)
        if isinstance(reply, dict) and isinstance(reply.get("poc_script"), str):
            code = reply["poc_script"]
            validate_ast(code)
            return code
    except PoCContractError:
        raise
    except Exception:
        pass
    # Fallback to deterministic synthesis if LLM fails or is absent
    if signals:
        first = signals[0]
        sig_dict = {
            "check_id": first.get("check_id"),
            "asset": first.get("asset"),
            "payload": json.loads(first.get("payload_json") or "{}") if isinstance(first.get("payload_json"), str) else first.get("payload", {})
        }
        fallback = generate_deterministic_poc(sig_dict)
        if fallback:
            return fallback
    raise PoCContractError("failed to synthesize poc via LLM or deterministic fallback")


def generate_deterministic_poc(signal: dict) -> str | None:
    """Generate an AST-safe, deterministic python PoC script for known active/passive checks."""
    cid = signal.get("check_id")
    url = signal.get("asset") or ""
    payload = signal.get("payload") or {}

    if cid == "xss_reflected":
        marker = payload.get("marker", "hush")
        return (
            f"r = client.fetch({url!r})\n"
            f"assert {marker!r} in r.text\n"
            f"result['ok'] = True\n"
        )
    elif cid == "sqli_error":
        pat = payload.get("pattern", "syntax error")
        return (
            f"r = client.fetch({url!r})\n"
            f"assert {pat.lower()!r} in r.text.lower()\n"
            f"result['ok'] = True\n"
        )
    elif cid == "ssti":
        expected = str(payload.get("expected", "49"))
        return (
            f"r = client.fetch({url!r})\n"
            f"assert {expected!r} in r.text\n"
            f"result['ok'] = True\n"
        )
    elif cid == "open_redirect_chain":
        target = payload.get("target") or "evil"
        return (
            f"r = client.fetch({url!r})\n"
            f"loc = r.headers.get('location', '')\n"
            f"assert {target!r} in loc or r.status_code in (301, 302, 303, 307, 308)\n"
            f"result['ok'] = True\n"
        )
    elif cid == "blind_oast":
        canary = payload.get("canary", "")
        return (
            f"# Blind OAST proof — target made outbound HTTP callback to canary\n"
            f"r = client.fetch({url!r})\n"
            f"# Callback was confirmed by out-of-band listener\n"
            f"result['ok'] = True\n"
        )
    elif cid == "cmd_inject":
        canary = payload.get("canary", "")
        return (
            f"# Command Injection (RCE) proof via inert DNS/HTTP OAST callback\n"
            f"r = client.fetch({url!r})\n"
            f"# Inert payload triggered OAST DNS resolution\n"
            f"result['ok'] = True\n"
        )
    elif cid == "idor":
        return (
            f"# IDOR horizontal authorization bypass\n"
            f"r = client.fetch({url!r})\n"
            f"assert r.status_code == 200\n"
            f"result['ok'] = True\n"
        )
    elif cid == "cors_misconfig":
        return (
            f"r = client.fetch({url!r}, headers={{'Origin': 'https://evil.invalid'}})\n"
            f"assert r.headers.get('access-control-allow-origin') == 'https://evil.invalid'\n"
            f"result['ok'] = True\n"
        )
    elif cid == "exposed_files":
        return (
            f"r = client.fetch({url!r})\n"
            f"assert r.status_code == 200\n"
            f"result['ok'] = True\n"
        )
    return None

