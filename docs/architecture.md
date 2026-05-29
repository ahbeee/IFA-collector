# IFA Collector Architecture

This MVP is built around a small invariant: always preserve the original bytes, even when the collector cannot fully interpret the metadata yet.

## Pipeline

```text
input
  -> packet decoder
  -> IFA header parser
  -> schema metadata parser
  -> fragment reassembler
  -> JSON output / future storage
```

## Inputs

Current:

- `parse-pcap`: Ethernet pcap frames.
- `listen-udp`: raw IFA payloads sent over UDP for lab testing.
- IPFIX v10 data set wrapper detection for Broadcom SONiC collector exports.
- `ingest-pcap`: parse pcap files into SQLite tables for UI/query use.

Planned:

- Mirrored packet receiver with configurable IFA protocol number.
- Broadcom Enterprise SONiC TAM collector wrapper detection once real collector payloads are available.

## Schema Model

Vendor metadata stacks are described by JSON files under `schemas/`.

Schema matching currently uses:

- IFA version.
- GNS.
- LNS from the first 4 metadata bits when the schema declares one.

Each field is decoded from a bit offset and bit width. This keeps the parser useful for compact switch ASIC formats where fields are not byte-aligned.

## Reverse Engineering Workflow

1. Capture pcap from the target device.
2. Run `parse-pcap` with no custom schema and inspect raw 4-byte words.
3. Add or adjust a JSON schema.
4. Compare decoded values with switch CLI or vendor UI.
5. Add a regression test using the smallest non-sensitive sample bytes.

## Known Limits

- IPFIX templates are not decoded yet.
- Fragment reassembly tracks completeness but does not merge metadata stacks yet.
- Topology and device inventory are not implemented yet.
- Queue depth and timestamp accuracy depend on vendor schema and clock configuration.
- Broadcom Enterprise SONiC configuration is documented in `docs/broadcom-sonic-ifa.md`, but the IFA collector report payload and metadata schema still need pcap/vendor schema confirmation.
- Aruba AOS-CX IFA metadata is documented in `docs/aruba-aoscx-ifa.md` and implemented as `schemas/aruba_aoscx_lns1.json`.

## SQLite Tables

`ingest-pcap` writes:

- `exporters`: IPFIX exporter health, sequence ranges, gaps, duplicate/reordered counts.
- `flows`: decoded original flow keys from clipped packets.
- `ifa_records`: one row per IFA record, including metadata-order path and traffic-order path.
- `hops`: one row per per-hop metadata block, resolved through inventory when available.
- `parse_errors`: non-IFA packets or malformed records observed while replaying a pcap.

Example:

```powershell
python -m ifa_collector.cli ingest-pcap .\ifa.pcap --inventory .\inventory\lab_topology.json --db .\ifa.sqlite
python -m ifa_collector.cli query --db .\ifa.sqlite flows --pretty
```
