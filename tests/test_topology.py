from ifa_collector.topology import fetch_device_metadata, parse_targets


def test_parse_targets_deduplicates_mixed_input():
    assert parse_targets("192.0.2.1, 192.0.2.1 192.0.2.2") == ["192.0.2.1", "192.0.2.2"]


def test_parse_targets_supports_cidr_and_range():
    assert parse_targets("192.0.2.0/30 192.0.2.5-192.0.2.6") == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.5",
        "192.0.2.6",
    ]


def test_fetch_device_metadata_normalizes_sonic_payloads():
    class FakeClient:
        def get_json(self, path):
            payloads = {
                "openconfig-system:system/state": {
                    "openconfig-system:state": {"hostname": "Border1"}
                },
                "openconfig-tam:tam/switch": {
                    "openconfig-tam:switch": {"state": {"switch-id": 1001, "enterprise-id": 4434}}
                },
                "openconfig-platform:components/component=System%20Eeprom": {
                    "openconfig-platform:component": [
                        {
                            "name": "System Eeprom",
                            "state": {
                                "description": "x86_64-accton_as7326_56x-r0",
                                "id": "7326-56X-O-AC-F",
                                "serial-no": "732656X1831011",
                            },
                        }
                    ]
                },
                "sonic-device-metadata-state:sonic-device-metadata-state/DEVICE_METADATA_STATE/DEVICE_METADATA_STATE_LIST=localhost/intf_naming_mode": {
                    "sonic-device-metadata-state:intf_naming_mode": "native"
                },
                "sonic-port:sonic-port/PORT_TABLE": {
                    "sonic-port:PORT_TABLE": {
                        "PORT_TABLE_LIST": [
                            {
                                "ifname": "Ethernet48",
                                "alias": "Eth1/49",
                                "index": 48,
                                "lanes": "77,78,79,80",
                                "speed": "100000",
                                "admin_status": "up",
                                "oper_status": "up",
                            }
                        ]
                    }
                },
            }
            return payloads[path]

    metadata = fetch_device_metadata(FakeClient())

    assert metadata["hostname"] == "Border1"
    assert metadata["switch_id"] == 1001
    assert metadata["platform"] == "x86_64-accton_as7326_56x-r0"
    assert metadata["product_name"] == "7326-56X-O-AC-F"
    assert metadata["interface_naming_mode"] == "native"
    assert metadata["interfaces"]["Ethernet48"]["ifindex"] == 49
