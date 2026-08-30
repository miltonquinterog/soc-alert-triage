from __future__ import annotations

from abc import ABC, abstractmethod

from soc_ai_agent.contracts.events import NormalizedEvent
from soc_ai_agent.ingestion.jsonl import RawJsonRecord


class Normalizer(ABC):
    @abstractmethod
    def normalize(self, record: RawJsonRecord) -> NormalizedEvent:
        raise NotImplementedError
