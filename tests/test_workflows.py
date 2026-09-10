import pytest

from hushhunt.workflows import Workflow, WorkflowStep, execute_workflow


def test_workflow_state_machine():
    import httpx

    # Mock server tracking resource creation and IDOR access
    data_store = {}

    def handler(request: httpx.Request):
        url = str(request.url)
        auth = request.headers.get("Authorization", "")
        if request.method == "POST" and "/api/items" in url:
            data_store["item_101"] = {"owner": "acct_a", "secret": "confidential_data"}
            return httpx.Response(201, json={"id": "item_101"})
        if request.method == "GET" and "/api/items/item_101" in url:
            # IDOR vulnerability: returns object regardless of auth
            return httpx.Response(200, json=data_store.get("item_101", {}))
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))

    wf = Workflow(name="idor_item_leak", steps=[
        WorkflowStep(
            action="post",
            url="https://t.invalid/api/items",
            session="session_a",
            extract={"item_id": "id"}
        ),
        WorkflowStep(
            action="get",
            url="https://t.invalid/api/items/{item_id}",
            session="session_b",
            assert_in="confidential_data"
        )
    ])

    result = execute_workflow(wf, sessions={"session_a": client, "session_b": client})
    assert result["success"] is True
    assert result["extracted"]["item_id"] == "item_101"
