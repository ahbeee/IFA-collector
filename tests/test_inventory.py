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


def test_inventory_updates_from_restconf_metadata_lanes() -> None:
    inventory = Inventory()
    inventory.upsert_device_metadata(
        {
            "switch_id": 1001,
            "hostname": "Border1",
            "product_name": "7326-56X-O-AC-F",
            "interfaces": {
                "Ethernet0": {"name": "Ethernet0", "alias": "Eth1/1", "lanes": "3", "speed": "10000"},
                "Ethernet48": {"name": "Ethernet48", "alias": "Eth1/49", "lanes": "77,78,79,80", "speed": "100000"},
            },
        }
    )

    resolved = inventory.resolve_hops(
        [
            HopMetadata(
                raw=b"",
                fields={"device_id": 1001, "ingress_logical_port": 3, "egress_logical_port": 79},
            )
        ]
    )

    assert resolved[0]["device_name"] == "Border1"
    assert resolved[0]["model"] == "7326-56X-O-AC-F"
    assert resolved[0]["ingress"]["interface"] == "Ethernet0"
    assert resolved[0]["ingress"]["front_panel"] == "Eth1/1"
    assert resolved[0]["egress"]["interface"] == "Ethernet48"
    assert resolved[0]["egress"]["front_panel"] == "Eth1/49"
    assert inventory.stats() == {"devices": 1, "logical_ports": 5}


def test_inventory_updates_from_saved_topology_metadata() -> None:
    inventory = Inventory()
    inventory.update_from_topology(
        {
            "graph": {
                "nodes": [
                    {
                        "id": "Border1",
                        "metadata": {
                            "switch_id": 1001,
                            "product_name": "7326-56X-O-AC-F",
                            "interfaces": {
                                "Ethernet0": {"name": "Ethernet0", "alias": "Eth1/1", "lanes": "3", "speed": "10000"}
                            },
                        },
                    }
                ]
            }
        }
    )

    hop = HopMetadata(raw=b"", fields={"device_id": 1001, "ingress_logical_port": 3})
    resolved = inventory.resolve_hop(hop)

    assert resolved["device_name"] == "Border1"
    assert resolved["ingress"]["interface"] == "Ethernet0"
