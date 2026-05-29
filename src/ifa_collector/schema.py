from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bitfield import read_bits
from .models import HopMetadata


@dataclass(frozen=True)
class FieldSpec:
    name: str
    offset_bits: int
    width_bits: int
    unit: str | None = None
    scale: float | None = None
    enum: dict[int, str] | None = None


@dataclass(frozen=True)
class MetadataSchema:
    schema_id: str
    vendor: str
    ifa_version: int
    gns: int
    lns: int | None
    hop_metadata_size: int
    fields: list[FieldSpec]

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> "MetadataSchema":
        fields = []
        for item in doc.get("fields", []):
            enum = item.get("enum")
            parsed_enum = {int(k): v for k, v in enum.items()} if enum else None
            fields.append(
                FieldSpec(
                    name=item["name"],
                    offset_bits=int(item["offset_bits"]),
                    width_bits=int(item["width_bits"]),
                    unit=item.get("unit"),
                    scale=float(item["scale"]) if "scale" in item else None,
                    enum=parsed_enum,
                )
            )

        return cls(
            schema_id=doc.get("id") or f"{doc['vendor']}:gns{doc['gns']}:lns{doc.get('lns', 'any')}",
            vendor=doc["vendor"],
            ifa_version=int(doc.get("ifa_version", 2)),
            gns=int(doc["gns"]),
            lns=int(doc["lns"]) if doc.get("lns") is not None else None,
            hop_metadata_size=int(doc["hop_metadata_size"]),
            fields=fields,
        )

    def decode_hop(self, data: bytes) -> HopMetadata:
        if len(data) != self.hop_metadata_size:
            raise ValueError(f"expected {self.hop_metadata_size} bytes, got {len(data)}")

        output: dict[str, Any] = {}
        for field in self.fields:
            value = read_bits(data, field.offset_bits, field.width_bits)
            if field.enum:
                output[field.name] = {
                    "raw": value,
                    "label": field.enum.get(value, f"unknown({value})"),
                }
            elif field.scale is not None:
                output[field.name] = value * field.scale
            else:
                output[field.name] = value

            if field.unit:
                output[f"{field.name}__unit"] = field.unit

        return HopMetadata(raw=data, fields=output, schema_id=self.schema_id)


class SchemaRegistry:
    def __init__(self, schemas: list[MetadataSchema] | None = None):
        self._schemas = schemas or []

    def add(self, schema: MetadataSchema) -> None:
        self._schemas.append(schema)

    def match(self, ifa_version: int, gns: int, hop_data: bytes) -> MetadataSchema | None:
        for schema in self._schemas:
            if schema.ifa_version != ifa_version or schema.gns != gns:
                continue
            if len(hop_data) < schema.hop_metadata_size:
                continue
            if schema.lns is None:
                return schema
            try:
                lns = read_bits(hop_data[: schema.hop_metadata_size], 0, 4)
            except ValueError:
                continue
            if lns == schema.lns:
                return schema
        return None

    @classmethod
    def load(cls, paths: list[Path]) -> "SchemaRegistry":
        registry = cls()
        for path in paths:
            if path.is_dir():
                files = sorted(path.glob("*.json"))
            else:
                files = [path]
            for file_path in files:
                with file_path.open("r", encoding="utf-8") as handle:
                    registry.add(MetadataSchema.from_dict(json.load(handle)))
        return registry

    @classmethod
    def load_default(cls) -> "SchemaRegistry":
        schema_dir = Path(__file__).resolve().parents[2] / "schemas"
        return cls.load([schema_dir]) if schema_dir.exists() else cls()
