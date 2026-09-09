from __future__ import annotations

import json
from dataclasses import dataclass

from .checks.active import ACTIVE_MODULES
from .grants import active_grant, risk_allows
from .policy_lint import allowed_module
from .scope import url_in_scope


@dataclass
class PlannedTest:
    module: str
    url: str
    param: str
    why: str

    def key(self) -> tuple:
        return (self.module, self.url, self.param)


PLAN_SYSTEM = """You are the follow-up test planner for an authorized passive
recon pipeline (v1) that just found context signals on a bug bounty program.
You may ONLY propose tests from this module list:
{{ modules }}
Propose at most 3 tests, as strict JSON:
{"tests":[{"module":"...","url":"...","param":"...","why":"one line"}]}
Rules: urls and params MUST come from the observed surface provided
(apis_seen/params_seen). Anything you invent is rejected by a validator, so
don't. Prefer routes leaked in js_endpoints context over guessing."""


def build_prompt(context: dict) -> tuple[str, str]:
    mods = "\n".join(f"- {m} (scope {sc})" for m, sc in sorted(ACTIVE_MODULES.items()))
    system = PLAN_SYSTEM.replace("{{ modules }}", mods)
    return system, json.dumps(context, indent=1, default=str)[:8000]


def validate(pt: PlannedTest, program: dict, conn, now=None,
             lint_blocked: set[str] | None = None,
             demoted: set[str] | None = None) -> str | None:
    """Returns None if the proposal may run, else the rejection reason.
    Order matters: cheap deterministic checks first, DB grant last."""
    if pt.module not in ACTIVE_MODULES:
        return "unknown_module"
    if demoted and pt.module in demoted:
        return "auto_demoted"
    if lint_blocked and not allowed_module(lint_blocked, pt.module):
        return "policy_blocked"
    if not url_in_scope(pt.url, program["includes"], program["excludes"]):
        return "out_of_scope"
    cap = program.get("risk_cap", "passive")
    if not risk_allows(cap, _module_risk(pt.module)):
        return "risk_cap"
    scope_needed = ACTIVE_MODULES[pt.module]
    if active_grant(conn, program["id"], pt.module, scope_needed, now=now) is None:
        return "no_grant"
    return None


_RISKS = {"xss_reflected": "medium", "xss_dom": "low", "sqli_error": "medium",
          "sqli_boolean": "high", "ssti": "medium", "idor": "high",
          "jwt_misuse": "medium", "open_redirect_chain": "low",
          "graphql_probe": "low", "blind_oast": "high", "mass_assign": "high"}


def _module_risk(module: str) -> str:
    return _RISKS.get(module, "high")    # unknown risks fail CLOSED


def plan(cfg, conn, llm, program: dict, context: dict,
         lint_blocked: set[str] | None = None,
         demoted: set[str] | None = None) -> list[PlannedTest]:
    """LLM proposes -> validator disposes. Invalid proposals go to
    out/planner_rejected.log (auditable). The model can NEVER widen its own
    permissions; every byte executed passed validate() against operator-set
    gates."""
    system, user = build_prompt(context)
    reply = llm.complete_json(system, user)
    out_dir = cfg.root / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    approved: list[PlannedTest] = []
    observed_params = {(p.get("url_path"), p.get("param"))
                       for p in context.get("params_seen", [])}
    seen_keys: set[tuple] = set()
    for raw in (reply.get("tests") or [])[:3]:
        try:
            pt = PlannedTest(str(raw["module"]), str(raw["url"]),
                             str(raw["param"]), str(raw.get("why", ""))[:200])
        except (KeyError, TypeError):
            _reject(out_dir, raw, "bad_shape")
            continue
        if (pt.url, pt.param) not in observed_params:
            _reject(out_dir, pt.key(), "invented_surface")
            continue
        reason = validate(pt, program, conn, lint_blocked, demoted)
        if reason:
            _reject(out_dir, pt.key(), reason)
            continue
        if pt.key() in seen_keys:
            continue
        seen_keys.add(pt.key())
        approved.append(pt)
    return approved


def _reject(out_dir, key, reason):
    with (out_dir / "planner_rejected.log").open("a", encoding="utf-8") as fh:
        fh.write(f"{json.dumps(key, default=str)} :: {reason}\n")
