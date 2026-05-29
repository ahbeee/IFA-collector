# Aruba AOS-CX IFA Notes

Sources:

- AOS-CX 10.17 Monitoring Guide Help Center, Inband Flow Analyzer (IFA)
- AOS-CX 10.17 Monitoring Guide Help Center, Inband Flow Analyzer Packet Headers
- AOS-CX 10.17 Monitoring Guide Help Center, Important considerations

## Collector Value

The Aruba documentation is directly useful for the collector because it documents a concrete IFA v2 metadata stack:

- IFA Version: `2.0`
- GNS: `0xF`
- LNS: `1`
- Probe packet IP protocol number: `253`
- Flags: unused
- Per-hop metadata size: `32` bytes
- Initiator adds 40 bytes:
  - 4-byte IFA header
  - 4-byte IFA metadata header
  - 32-byte IFA metadata stack
- Transit nodes add another 32-byte metadata stack per hop.

This is already represented by `schemas/aruba_aoscx_lns1.json`.

## Metadata Fields

The AOS-CX IFA metadata stack contains:

- LNS
- Device ID
- IP TTL
- Egress Port Speed
- Congestion
- Queue ID
- Rx Timestamp Seconds
- Egress Port Number
- Ingress Port Number
- Rx Timestamp Nanoseconds
- Residence Time Nanoseconds
- Opaque Data 1: egress queue transmission bytes
- Opaque Data 2 High: reserved
- Opaque Data 2 Low: queue depth in cells
- Opaque Data 3: queue pool available in cells

Egress port speed encoding:

- `0`: 10G
- `1`: 25G
- `2`: 40G
- `3`: 50G
- `4`: 100G
- `5`: 200G
- `6`: 400G

## Platform and Traffic Limits

The AOS-CX 10.17 page says IFA is applicable only on 8325 and 9300 switch series.

Important constraints:

- Only probe packets are supported.
- Only UDP and TCP protocols are supported.
- Broadcast, unknown unicast, and multicast are not supported.
- IPv6 extension headers are not supported.
- TCP packets with options are not supported.
- 1588 UDP frames are not supported.
- VXLAN and GRE tunneled traffic are not supported.
- Initiating IFA traffic on a LAG interface is not supported.
- To obtain end-to-end metrics, all traversed devices must have IFA enabled.
- Terminator flow metrics are limited; public 10.15 docs mention 1000 flows on a terminator.

## Collector Implications

For pcap parsing, AOS-CX IFA should appear as an IPv4 or IPv6 packet with protocol/next-header `253`, followed by the IFA header.

For UI interpretation:

- Device ID must be mapped through inventory to switch names.
- Hardware ingress/egress port numbers must be mapped to interfaces.
- Queue depth is in cells, not percent.
- Congestion requires ECN on the egress port.
- Residence time is already per-hop latency in nanoseconds.

## Open Questions

The documentation helps with parsing probe packets, but it does not fully answer external collector transport for every deployment. A real pcap from the collector port is still needed to confirm whether the collector receives:

- Raw IFA probe packets.
- CPU-generated metrics reports.
- A vendor wrapper around clipped packets.
- REST-only terminator metrics without packet export.
