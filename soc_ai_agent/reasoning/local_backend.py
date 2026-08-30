from .contracts import ReasoningRequest, ReasoningResponse
from .errors import BackendUnavailable


class LocalReasoningBackend:
    """Reserva de interfaz para runtime local futuro; no realiza llamadas."""
    backend_name = "local"
    backend_version = "interface-only-v1"
    model_name = None

    def reason(self, request: ReasoningRequest) -> ReasoningResponse:
        raise BackendUnavailable("LocalReasoningBackend is not configured in this phase")
