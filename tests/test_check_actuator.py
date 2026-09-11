from hushhunt.checks.active.actuator import check_actuator
from hushhunt.checks import Ctx

class MockResp:
    def __init__(self, status_code, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text or ""

    def json(self):
        if self._json is not None:
            return self._json
        raise ValueError("no json")

class MockFetch:
    def __init__(self, routes):
        self.routes = routes

    def __call__(self, url, **kwargs):
        for route, resp in self.routes.items():
            if route in url:
                return resp
        return MockResp(404)

def test_actuator_exposed_git_leak():
    routes = {
        "/actuator/info": MockResp(200, json_data={"git": {"commit": {"id": "a9987d1"}, "branch": "main"}}),
        "/actuator": MockResp(200, json_data={"_links": {"self": {"href": "/actuator"}}})
    }
    fetch = MockFetch(routes)
    ctx = Ctx(resp=None, fetch=fetch, asset_url="https://api.example.com")
    signals = list(check_actuator(ctx))
    assert len(signals) >= 1
    assert signals[0]["check_id"] == "actuator_git_leak"
    assert "a9987d1" in signals[0]["payload_json"]

def test_actuator_closed():
    fetch = MockFetch({})
    ctx = Ctx(resp=None, fetch=fetch, asset_url="https://api.example.com")
    signals = list(check_actuator(ctx))
    assert len(signals) == 0
