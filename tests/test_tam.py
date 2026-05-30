from ifa_collector import tam
from ifa_collector.topology import RestconfAuth, RestconfDevice


def test_clear_flowgroup_counters_uses_restconf_action(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def post_operation(self, path, payload=None):
            calls.append((path, payload, self.kwargs["host"]))
            return {"openconfig-tam:output": {"status": 0}}

    monkeypatch.setattr(tam, "RestconfClient", FakeClient)
    devices = [RestconfDevice("10.0.0.1", RestconfAuth("admin", "admin"))]

    result = tam.clear_flowgroup_counters(devices, ["fg_a", "all"])

    assert result["summary"] == {"requests": 2, "errors": 0}
    assert calls == [
        (
            "openconfig-tam:clear-flowgroup-counters",
            {"openconfig-tam:input": {"name": "fg_a"}},
            "10.0.0.1",
        ),
        (
            "openconfig-tam:clear-flowgroup-counters",
            {"openconfig-tam:input": {"name": "all"}},
            "10.0.0.1",
        ),
    ]
