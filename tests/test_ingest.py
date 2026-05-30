from pathlib import Path

from ifa_collector.ingest import ingest_pcap
from ifa_collector.query import QueryStore
from ifa_collector.schema import SchemaRegistry


def test_ingest_pcap_writes_records(tmp_path: Path) -> None:
    db = tmp_path / "ifa.sqlite"
    result = ingest_pcap(Path("IFA udp.pcap"), db, SchemaRegistry.load_default())

    assert result.parsed_ifa_records == 125
    assert result.parse_errors == 0
    assert result.import_id == 1
    assert result.imported_at_ns is not None

    store = QueryStore(db)
    try:
        assert store.flows(1)
        assert store.paths(1)
        imports = store.import_runs()
        assert imports[0]["source"].endswith("IFA udp.pcap")
        assert imports[0]["parsed_ifa_records"] == 125
        assert imports[0]["parse_errors"] == 0
        assert store.recent_records(import_id=result.import_id)[0]["import_id"] == result.import_id
    finally:
        store.close()
