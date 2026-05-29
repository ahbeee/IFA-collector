# Broadcom Enterprise SONiC IFA Notes

Source: `IFA.pdf`, Enterprise SONiC Distribution by Broadcom User Guide, SONiC 4.5.0, Chapter 24.

## What This Adds

The PDF confirms the operational model for Broadcom Enterprise SONiC TAM IFA:

- IFA is configured under TAM.
- Switch-wide `switch-id` is a 32-bit TAM switch identifier.
- `enterprise-id` is a 32-bit identifier used in telemetry reports.
- IFA roles are configured per flow/session:
  - ingress
  - transit
  - egress
- Ingress nodes require sampler configuration.
- Transit nodes do not require sampler or collector configuration.
- Egress nodes require collector configuration.
- Egress nodes extract/summarize metadata and send it to a configured collector.

## Useful CLI Surface

Global TAM:

```text
tam
  switch-id <id>
  enterprise-id <id>
```

Sampler:

```text
sampler <name> rate <sampler_rate>
```

Flow group:

```text
flow-group <name>
  [src-ip <address/prefix>]
  [dst-ip <address/prefix>]
  [src-l4-port <port>]
  [dest-l4-port <port>]
  [priority <value>]
  [protocol TCP|UDP]
```

Collector:

```text
collector <name> ip <collector_ip> port <port> [protocol UDP|TCP] [vrf <vrf-name>]
```

IFA session examples:

```text
tam
  ifa
    enable
    session <session-name> flowgroup <flowgroup-name> sample-rate <sampler-name> node-type ingress
```

```text
tam
  ifa
    enable
    session <session-name> flowgroup <flowgroup-name> collector <collector-name> node-type egress
```

Verification commands:

```text
show tam features
show tam ifa
show tam ifa sessions
show tam samplers
show tam flowgroups
show tam collectors
show tam switch
```

## Collector Implications

For Broadcom Enterprise SONiC, the collector should expect data from the egress node on a configured UDP or TCP port. The guide says monitored IFA metadata is sent to the collector, but this excerpt does not define the exact IFA collector payload format.

Important config values to capture beside packet data:

- `switch-id`: maps to device identity in reports and UI.
- `enterprise-id`: likely needed to interpret vendor telemetry reports.
- collector name/IP/port/protocol.
- flow group name and match criteria.
- session name and role.
- sampler name and rate.
- ingress interface flow-group binding.

## What Is Still Missing

The PDF does not appear to provide:

- Broadcom IFA metadata stack bit layout.
- GNS/LNS values used by Broadcom SONiC.
- Whether IFA collector export is raw IFA packet, proprietary TAM report, protobuf, or another wrapper.
- IFA report protobuf schema.
- timestamp units and queue-depth encoding for IFA.
- device/port/queue mapping beyond the configured TAM switch ID.

The protobuf shown in this PDF is for packet-drop monitoring reports, not clearly for IFA reports.

## Observed Collector Packet

`IFA udp.pcap` shows Broadcom SONiC exporting IFA records as IPFIX over UDP:

- UDP source port: `9070`
- UDP destination port: configured collector port `9090`
- IPFIX version: `10`
- Observation Domain ID: `0x12345678` in the sample
- Data Set ID: `257`
- Data Set payload starts with the IFA header

The IFA record in the sample:

- IFA header starts with `2f 11 00 ff`
  - version `2`
  - GNS `15`
  - original protocol `17` / UDP
  - max length `255` words
- metadata header is `ff ff 1e 10`
  - request vector `255`
  - action vector `255`
  - hop limit `30`
  - current metadata length `16` words / `64` bytes
- two 32-byte metadata hops follow
- the remaining record bytes are a clipped copy of the original packet

The sample metadata contains the configured switch IDs:

- `0x03ea` / `1002`
- `0x03e9` / `1001`

An inferred schema is provided at `schemas/broadcom_sonic_inferred_lns_any.json`. It is intentionally conservative: only `device_id` and `ip_ttl` should be treated as reasonably confirmed from current samples. Other fields are exposed as raw or tentative byte/word fields until vendor documentation or more validation data is available.

Current port-field inference from forward and reverse three-switch pcaps:

- Bytes 12 and 14 inside each 32-byte hop appear to be egress and ingress ASIC port IDs.
- Forward flow `1.1.1.1 -> 4.4.4.4`:
  - Border1 / 1001: egress `79`, ingress `3`
  - Transit / 1003: egress `95`, ingress `91`
  - Border2 / 1002: egress `3`, ingress `79`
- Reverse flow `4.4.4.4 -> 1.1.1.1`:
  - Border2 / 1002: egress `79`, ingress `3`
  - Transit / 1003: egress `91`, ingress `95`
  - Border1 / 1001: egress `3`, ingress `79`

For Border1, `show interface status` confirms the active path ports are `Ethernet0` toward Server1 and `Ethernet48` toward Transit. The observed IDs suggest:

- `Ethernet0` maps to internal port ID `3`
- `Ethernet48` maps to internal port ID `79`

The schema names these fields `egress_logical_port` and `ingress_logical_port`.

Additional interface status output confirms the same pattern on the current lab topology:

- Border2:
  - `Ethernet0` / `Eth1/1` maps to internal port ID `3`
  - `Ethernet48` / `Eth1/49` maps to internal port ID `79`
- Transit:
  - `Ethernet88` / `Eth1/23` maps to internal port ID `91`
  - `Ethernet92` / `Eth1/24` maps to internal port ID `95`

Observed forward path `Server1 -> Border1 -> Transit -> Border2 -> Server2`:

- Border1: ingress `Ethernet0` / ID `3`, egress `Ethernet48` / ID `79`
- Transit: ingress `Ethernet88` / ID `91`, egress `Ethernet92` / ID `95`
- Border2: ingress `Ethernet48` / ID `79`, egress `Ethernet0` / ID `3`

Observed reverse path confirms the fields swap as expected.

Border2 `bcmsh ps` confirms these are Broadcom SDK logical port numbers:

- `xe0(3)` is up at 10G and corresponds to SONiC `Ethernet0` / `Eth1/1`.
- `ce0(79)` is up at 100G and corresponds to SONiC `Ethernet48` / `Eth1/49`.

So the field confidence is now:

- byte 12: confirmed `egress_logical_port`
- byte 14: confirmed `ingress_logical_port`

Transit `bcmsh ps` confirms the same for the 32x100G platform:

- `ce22(91)` is up and corresponds to SONiC `Ethernet88` / `Eth1/23`.
- `ce23(95)` is up and corresponds to SONiC `Ethernet92` / `Eth1/24`.

Forward Transit metadata uses egress `95`, ingress `91`; reverse metadata uses egress `91`, ingress `95`, matching the physical path.

## Broadcom Packet Processing Guide Notes

Source: Broadcom `BCM88690 Packet Processing Programming Guide`, Chapter 50, Section 50.3, IFA 2.0.

The guide confirms the generic IFA 2.0 interpretation:

- IFA 2.0 is applied to sampled live traffic on StrataDNX devices.
- It is supported over IPv4 TCP/UDP.
- The initiator adds the IFA 2.0 header, initializes the metadata header, adds initiator metadata, and reinjects the packet.
- A transit node detects IFA 2.0 by IP protocol ID, checks current length and hop limit, adds local metadata, and updates current length/hop limit.
- A terminator can terminate with or without adding its own metadata; it sends a copy to the collector, strips IFA headers and metadata stack from the original packet, and forwards the original packet.
- IFA header fields:
  - Version: 4 bits, value `0x2`
  - GNS: 4 bits, value `0xf`
  - Protocol Type: original IP protocol, for example TCP/UDP
  - Outer IPv4 protocol used for IFA defaults to `253`
  - Max Length is measured in 4-octet words
- Metadata header fields:
  - Request Vector: 8 bits, guide example `0xff`
  - Action Vector: 8 bits, guide example `0x0`
  - Hop Limit: 8 bits
  - Current Length: 8 bits, measured in 4-octet words
  - Guide says current length is initialized to `8` and incremented by `8` per node, meaning 32 bytes per metadata node.

This aligns with the pcap on the high-level structure:

- GNS is `15`.
- Metadata current length `16` means `64` bytes.
- The pcap contains two 32-byte hop metadata records.

However, the same guide says the first 4 bytes of each metadata record are `LNS + device ID`. The observed SONiC pcap does not place the configured switch IDs (`1002` / `1001`) in the first 4 bytes of each 32-byte hop. In the observed export, the switch IDs appear at bytes 4-5 within each hop record.

For this reason, the guide is useful for the IFA 2.0 envelope and hop sizing, but it does not fully confirm the Broadcom SONiC hop metadata bit layout. Keep the current Broadcom schema marked as inferred until a SONiC-specific metadata description or more counter/port/latency correlation samples are available.

## Broadcom IPFIX Chapter Notes

Source: Broadcom `BCM88690 Packet Processing Programming Guide`, Chapter 52, Instrumentation - IPFIX.

Chapter 52 appears to describe the export mechanism that SONiC is using for IFA collector reports:

- Samples are sent to the Eventor and aggregated.
- Records are exported to a collector after a configurable number of records has been gathered.
- The IPFIX export packet uses:
  - Version: `0x000a`
  - Length: full IPFIX packet length
  - Export Time: transmission time in seconds
  - Sequence Number: export packet sequence
  - Observation Domain: configured 32-bit value
- Global IPFIX configuration includes:
  - setup time
  - template ID
  - eventor header/context
  - export time
  - observation domain
  - stat counter for sequence number
- Eventor builder configuration controls the predefined outer packet header and when an IPFIX datagram is emitted.

This matches `IFA udp.pcap`:

- UDP payload starts with IPFIX version `00 0a`.
- IPFIX length is `00 a0` / 160 bytes.
- Export time and sequence number are populated.
- Observation domain in the sample is `0x12345678`.
- Data Set ID `257` carries the IFA record.

Important distinction:

- Chapter 52's standalone IPFIX record fields describe a normal sampled-flow IPFIX record with fields such as SIP, DIP, L4 ports, ingress/egress VRF, ingress/egress interface, and setup time.
- The observed SONiC IFA export does not use that standalone fixed IPFIX record layout directly. Instead, the IPFIX data set payload starts with the IFA 2.0 header, metadata header, metadata stack, and a clipped original packet.

Collector behavior should therefore be:

1. Decode IPFIX header and data sets using RFC 7011 structure.
2. Treat unknown data set IDs >= 256 as enterprise/application payloads.
3. If a data set payload starts with an IFA v2 header (`version=2`, `GNS=15`), pass it to the IFA parser.
4. Do not assume Chapter 52's normal flow-record field layout for IFA data sets unless a future pcap shows a matching template/data-set pair.

## RFC 5470 / RFC 7011 / BroadView Notes

BroadView Instrumentation references RFC 5470 and RFC 7011 because its flow tracker exports flow records using IPFIX. The BroadView product brief is useful context, but it describes flow-based monitoring/flow tracker rather than the IFA 2.0 per-hop metadata export observed in `IFA udp.pcap`.

Useful points from the BroadView product brief:

- BroadView exports flow records in IPFIX format to a remote collector.
- IPFIX export is template-based.
- IPFIX supports proprietary information elements.
- The brief names ntopng as an example IPFIX-capable collector, but says it was used for demonstration and must be sourced separately.
- BroadView flow tracker exports over UDP at a configurable interval, with 100 ms granularity in the brief.

Useful points from RFC 5470:

- IPFIX separates the exporter, metering process, observation domain, and collector roles.
- A flow record can include packet header properties and packet-treatment properties such as output interface.
- Observation Domain ID identifies the observation domain for a given exporting process. In our pcap, this appears as `0x12345678`.
- Templates are control information required for a collector to understand generic IPFIX data records.

Useful points from RFC 7011 for the collector implementation:

- IPFIX version is `0x000a`.
- Set ID `2` is a Template Set.
- Set ID `3` is an Options Template Set.
- Set IDs `256+` are Data Sets.
- For UDP, there is no real connection setup or shutdown.
- UDP IPFIX is lossy; the collector must use IPFIX Sequence Number gaps to detect lost, duplicate, or reordered exports.
- Template IDs over UDP are scoped by exporter/source UDP port, collector destination, observation domain, and template ID.
- A collector may buffer Data Records temporarily if their Template has not arrived yet.
- Template withdrawals must not be used over UDP.

Impact on this project:

- Keep the current IPFIX parser template-aware even though the observed IFA data set does not include a Template Set.
- Track exporter sessions by source IP, source port, destination IP, destination port, and observation domain.
- Track IPFIX sequence gaps per exporter session.
- Continue to treat Set ID `257` as a Broadcom SONiC IFA application data set only after checking that the payload starts with an IFA v2 header.
- If future packets include Template Sets, store them, but do not assume the IFA data set follows a normal IPFIX fixed-field record layout unless the template says so.

## ntopng / nProbe Notes

ntopng supports IPFIX-based flow visualization, but the current ntop documentation recommends nProbe as the collector/normalizer in serious deployments. nProbe listens for NetFlow/IPFIX/sFlow, normalizes/enriches records, and forwards a clean stream to ntopng, commonly over ZMQ.

Relevant ntop/nProbe capabilities to borrow:

- exporter inventory and per-exporter statistics
- live flow table
- historical flow search
- time-series charts
- alerting on thresholds/anomalies
- local/site grouping
- GeoIP/AS enrichment for regular flow records
- collector scaling through a separate ingestion component
- custom/proprietary IPFIX field support through field definitions

Limit for IFA:

nProbe custom fields help when a vendor exports proper IPFIX Templates and proprietary Information Elements. Our observed Broadcom SONiC IFA export uses IPFIX as a transport wrapper where the Data Set payload starts with a raw IFA record. Unless SONiC also exports an IPFIX Template that describes the internal IFA fields, ntopng/nProbe will likely not decode per-hop IFA metadata out of the box.

Useful UI design inspiration from ntopng:

- flow list by 5-tuple, exporter, time, bytes, packets, and application when known
- exporter/source view with packet drops, sequence gaps, and collection health
- historical query over flow keys
- per-flow detail page with charts
- threshold alerts

IFA-specific additions beyond ntopng's normal flow model:

- per-flow hop path
- per-packet hop metadata
- device-id to switch-name mapping
- per-hop residence latency
- queue depth/congestion timeline
- raw IFA/IPFIX record inspection
- schema confidence labels: confirmed, inferred, unknown

## Development Impact

Add support in this order when Broadcom SONiC samples are available:

1. UDP/TCP collector input with source egress switch tracking.
2. Broadcom IPFIX wrapper parsing.
3. Broadcom schema refinement once hop metadata layout is validated.
4. Inventory importer for `show tam switch`, `show tam ifa sessions`, `show tam flowgroups`, and `show tam collectors`.
