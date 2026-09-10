"""Multi-step business logic state machine.

Chains stateful workflows across authenticated sessions (e.g. Account A
creates resource -> extracts ID -> Account B attempts access) to discover
true privilege escalation and IDOR vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkflowStep:
    action: str  # "get" or "post"
    url: str
    session: str = "session_a"
    json_data: dict | None = None
    extract: dict[str, str] = field(default_factory=dict)  # var_name -> json_key
    assert_in: str | None = None
    assert_status: int | None = None  # None = any 2xx accepted


@dataclass
class Workflow:
    name: str
    steps: list[WorkflowStep]


def execute_workflow(wf: Workflow, sessions: dict[str, Any]) -> dict:
    state: dict[str, Any] = {}
    history = []

    for i, step in enumerate(wf.steps):
        client = sessions.get(step.session)
        if client is None:
            return {"success": False, "error": f"missing session {step.session}"}

        # Substitute extracted variables in URL: e.g. {item_id}
        url = step.url.format(**state)

        try:
            if step.action == "post":
                resp = client.post(url, json=step.json_data or {})
            else:
                resp = client.get(url)
        except Exception as e:
            return {"success": False, "error": f"step {i} request failed: {e}"}

        history.append({"url": url, "status": resp.status_code, "text_snippet": resp.text[:200]})

        if step.assert_status is not None:
            if resp.status_code != step.assert_status:
                return {"success": False, "step": i, "status": resp.status_code, "history": history}
        elif not (200 <= resp.status_code < 300):
            return {"success": False, "step": i, "status": resp.status_code, "history": history}

        if step.assert_in and step.assert_in not in resp.text:
            return {"success": False, "step": i, "missing_assertion": step.assert_in, "history": history}

        # Extract values for next steps
        if step.extract:
            try:
                data = resp.json()
                for var_name, key in step.extract.items():
                    if isinstance(data, dict) and key in data:
                        state[var_name] = data[key]
            except Exception:
                pass

    return {"success": True, "extracted": state, "history": history}
