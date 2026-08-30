from typing import Protocol

from .contracts import ReasoningRequest, ReasoningResponse


class ReasoningBackend(Protocol):
    backend_name: str
    backend_version: str
    model_name: str | None

    def reason(self, request: ReasoningRequest) -> ReasoningResponse: ...
