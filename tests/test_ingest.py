from pathlib import Path

from ifa_collector.ingest import ingest_pcap
from ifa_collector.query import QueryStore
from ifa_collector.schema import SchemaRegistry


def test_ingest_pcap_writes_records(tmp_path: Path) -> None:
    db = tmp_path / "ifa.sqlite"
    result = ingest_pcap(Path("IFA udp.pcap"), db, SchemaRegistry.load_default())

    assert result.parsed_ifa_records == 125
    assert result.parse_errors == 0

    store = QueryStore(db)
    try:
        assert store.flows(1)
        assert store.paths(1)
    finally:
        store.close()
