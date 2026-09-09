from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import httpx


@dataclass
class CheckDef:
    id: str
    wstg: str        # OWASP WSTG v4.0 mapping — verified against the live index
    risk: str        # passive | low
    fn: Callable = None
    repro_steps: Callable = lambda sig: []


@dataclass
class Ctx:
    resp: httpx.Response
    fetch: Callable | None = None   # HardenedClient.get for checks allowed 1 extra req
    asset_url: str | None = None
    fetched_js: list = field(default_factory=list)  # bodies shared: fetch-once-evaluate-many
    params: list = field(default_factory=list)      # crawler [(url, param, orig)] v2
    grant_id: int | None = None                     # active checks carry their grant
    oast=None                                       # OastClient|FakeOast (v2 blind)
    sessions=None                                   # SessionBroker (v2 authed)
    post: Callable | None = None                    # HardenedClient.post (grant-gated)


CHECK_CATALOG: dict[str, CheckDef] = {}


def register(id_: str, wstg: str, risk: str):
    def deco(fn):
        CHECK_CATALOG[id_] = CheckDef(id_, wstg, risk, fn)
        return fn
    return deco


def register_repro(check_id: str, steps_fn: Callable):
    CHECK_CATALOG[check_id].repro_steps = steps_fn
