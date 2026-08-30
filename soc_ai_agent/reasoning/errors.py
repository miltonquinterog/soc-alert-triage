class ReasoningBackendError(Exception):
    code = "backend_error"
    def __init__(self, message="", response_status=None, incomplete_reason=None, *, provider_error_type=None,
                 http_status=None, provider_error_code=None, provider_error_param=None, technical_message=None):
        super().__init__(message)
        self.response_status = response_status
        self.incomplete_reason = incomplete_reason
        self.provider_error_type = provider_error_type
        self.http_status = http_status
        self.provider_error_code = provider_error_code
        self.provider_error_param = provider_error_param
        self.technical_message = technical_message
        self.response_diagnostic = None
        self.backend_diagnostic = None
        self.input_token_estimate = None
        self.failure_stage = None
        self.validation_path = None
        self.schema_rule = None
        self.expected_type = None
        self.received_type = None


class BackendUnavailable(ReasoningBackendError):
    code = "backend_unavailable"


class BackendTimeout(ReasoningBackendError):
    code = "backend_timeout"


class BackendMalformedResponse(ReasoningBackendError):
    code = "backend_malformed_response"


class BackendSchemaViolation(ReasoningBackendError):
    code = "backend_schema_violation"


class BackendRequestSchemaViolation(BackendSchemaViolation):
    """El schema de salida fue rechazado antes de generar una respuesta."""
    code = "backend_request_schema_violation"


class BackendResponseSchemaViolation(BackendSchemaViolation):
    """La respuesta del proveedor no coincide con el contrato de respuesta."""
    code = "backend_response_schema_violation"


class BackendTokenBudgetExceeded(ReasoningBackendError):
    code = "backend_token_budget_exceeded"


class BackendProviderRefusal(ReasoningBackendError):
    code = "backend_provider_refusal"
