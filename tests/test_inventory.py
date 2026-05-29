from pathlib import Path

from ifa_collector.inventory import Inventory
from ifa_collector.models import HopMetadata


def test_inventory_resolves_traffic_order_path() -> None:
    inventory = Inventory.load(Path("inventory/lab_topology.json"))
    hops = [
        HopMetadata(raw=b"", fields={"device_id": 1002, "ingress_logical_port": 79, "egress_logical_port": 3}),
        HopMetadata(raw=b"", fields={"device_id": 1003, "ingress_logical_port": 91, "egress_logical_port": 95}),
        HopMetadata(raw=b"", fields={"device_id": 1001, "ingress_logical_port": 3, "egress_logical_port": 79}),
    ]

    resolved = inventory.resolve_hops(hops, traffic_order=True)

    assert [hop["device_name"] for hop in resolved] == ["Border1", "Transit", "Border2"]
    assert resolved[0]["ingress"]["interface"] == "Ethernet0"
    assert resolved[0]["egress"]["interface"] == "Ethernet48"
