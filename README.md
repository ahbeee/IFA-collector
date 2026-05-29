# IFA Collector MVP

Schema-driven collector prototype for In-band Flow Analyzer (IFA) packets.

Current scope:

- Offline pcap replay.
- UDP listener for raw payload experiments.
- Ethernet, IPv4, IPv6, UDP, TCP, VXLAN, GRE, and Geneve traversal.
- IFA v2 base header, metadata header, checksum header, and fragmentation header parsing.
- JSON schema driven hop metadata decoding.
- Raw metadata fallback when no schema matches.
- Aruba AOS-CX GNS `0xF` / LNS `1` metadata schema.
- Broadcom SONiC IPFIX-over-UDP collector wrapper detection.
- RESTCONF topology scan from SONiC LLDP, port, LAG, and system state.
- Web UI topology tab with RESTCONF scan and stored topology rendering.

Example:

```powershell
python -m ifa_collector.cli parse-pcap .\sample.pcap --schema-dir .\schemas
python -m ifa_collector.cli parse-pcap .\sample.pcap --inventory .\inventory\lab_topology.json --summary --pretty
python -m ifa_collector.cli listen-udp --host 0.0.0.0 --port 4739 --schema-dir .\schemas
python -m ifa_collector.cli ingest-pcap .\sample.pcap --inventory .\inventory\lab_topology.json --db .\ifa.sqlite
python -m ifa_collector.cli query --db .\ifa.sqlite exporters --pretty
python -m ifa_collector.cli query --db .\ifa.sqlite flows --pretty
python -m ifa_collector.cli query --db .\ifa.sqlite paths --pretty
python -m ifa_collector.cli scan-topology "10.101.110.1,10.101.110.2" --username admin --password admin --no-ping --output .\topology\topology.json
python -m ifa_collector.cli scan-topology dummy --device 10.101.110.1,admin,admin --device 10.101.125.2,admin,password --output .\topology\topology.json
python -m ifa_collector.cli read-tam --device 10.101.110.1,admin,admin --device 10.101.125.2,admin,password
python -m ifa_collector.cli serve --db .\ifa.sqlite --port 8080 --topology-file .\topology\topology.json
```

The built-in schemas are intentionally examples. Real production accuracy depends on the switch vendor/model metadata format and collector export format.

RESTCONF topology scan currently expects these SONiC paths:

- `openconfig-lldp:lldp/interfaces`
- `sonic-port:sonic-port/PORT_TABLE`
- `sonic-portchannel:sonic-portchannel/LAG_TABLE`
- `openconfig-system:system/state`

RESTCONF TAM/IFA state read currently expects these SONiC paths:

- `openconfig-tam:tam/features-state/feature-state=IFA/state/op-status`
- `openconfig-tam:tam/features-state/feature-state`
- `openconfig-tam:tam/switch`
- `openconfig-tam:tam/collectors`
- `openconfig-tam:tam/flowgroups`
- `openconfig-tam:tam/ifa-sessions`
