from dataclasses import replace

from .contracts import BackendMetadata, ReasoningRequest, ReasoningResponse
from .errors import ReasoningBackendError


class DeterministicTestBackend:
    """Backend sin red. Consume una secuencia reproducible de respuestas o errores."""
    backend_name = "deterministic-test"
    backend_version = "1.0"
    model_name = None

    def __init__(self, outcomes: tuple[ReasoningResponse | Exception, ...]) -> None:
        self.outcomes = list(outcomes); self.calls = 0

    def reason(self, request: ReasoningRequest) -> ReasoningResponse:
        self.calls += 1
        if not self.outcomes: raise ReasoningBackendError("no deterministic outcome configured")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception): raise outcome
        metadata = outcome.backend_metadata or BackendMetadata(self.backend_name, self.backend_version, self.model_name,
            request.request_id, None, None, None, 0, 0, 0)
        return replace(outcome, backend_metadata=replace(metadata, request_id=request.request_id))
