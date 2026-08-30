from dataclasses import dataclass

from .events import DatasetRef


@dataclass(frozen=True)
class QuarantinedRecord:
    dataset: DatasetRef
    line_number: int
    raw_event: str
    parse_error: str
