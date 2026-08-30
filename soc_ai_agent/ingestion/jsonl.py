"""Lectura JSONL que preserva evidencia y pone errores en cuarentena."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from soc_ai_agent.contracts.events import DatasetRef
from soc_ai_agent.contracts.quarantine import QuarantinedRecord


@dataclass(frozen=True)
class RawJsonRecord:
    dataset: DatasetRef
    raw_event: str
    parsed: object


@dataclass(frozen=True)
class JsonlReadResult:
    records: tuple[RawJsonRecord, ...]
    quarantine: tuple[QuarantinedRecord, ...]


def _remove_delimiter(line: str) -> str:
    """Quita exclusivamente el delimitador físico de línea, nunca whitespace de evidencia."""
    if line.endswith("\r\n"):
        return line[:-2]
    if line.endswith("\n") or line.endswith("\r"):
        return line[:-1]
    return line


def read_jsonl(path: str | Path, dataset_name: str | None = None) -> JsonlReadResult:
    path = Path(path)
    name = dataset_name or path.name
    records: list[RawJsonRecord] = []
    quarantine: list[QuarantinedRecord] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, physical_line in enumerate(handle, start=1):
            raw_event = _remove_delimiter(physical_line)
            if raw_event == "":
                continue
            dataset = DatasetRef(name=name, format="jsonl", line_number=line_number)
            try:
                parsed = json.loads(raw_event)
            except json.JSONDecodeError as error:
                quarantine.append(QuarantinedRecord(
                    dataset=dataset,
                    line_number=line_number,
                    raw_event=raw_event,
                    parse_error=f"JSONDecodeError: {error.msg} (column {error.colno})",
                ))
                continue
            records.append(RawJsonRecord(dataset=dataset, raw_event=raw_event, parsed=parsed))
    return JsonlReadResult(tuple(records), tuple(quarantine))
