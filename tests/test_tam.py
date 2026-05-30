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


def test_preview_reports_tam_validation_errors():
    result = tam.preview_tam_plan(
        {
            "sessions": [
                {"name": "ifa_bad", "flowgroup": "fg_a", "node_type": "EGRESS", "sampler": "samp_a"}
            ]
        }
    )

    assert result["operations"] == []
    assert result["summary"]["errors"] == 2
    assert "egress IFA session ifa_bad collector is required" in result["errors"]
    assert "egress IFA session ifa_bad must not include sampler" in result["errors"]


def test_apply_blocks_invalid_tam_plan(monkeypatch):
    class FakeClient:
        def __init__(self, **kwargs):
            raise AssertionError("invalid plan should not open a RESTCONF client")

    monkeypatch.setattr(tam, "RestconfClient", FakeClient)
    devices = [RestconfDevice("10.0.0.1", RestconfAuth("admin", "admin"))]

    try:
        tam.apply_tam_plan(devices, {"collectors": [{"name": "bad", "ip": "192.0.2.1", "port": 0}]})
    except ValueError as exc:
        assert "collector bad port must be greater than zero" in str(exc)
    else:
        raise AssertionError("expected ValueError")
