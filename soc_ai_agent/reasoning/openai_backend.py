from .contracts import ReasoningRequest, ReasoningResponse
import re

from .errors import (BackendRequestSchemaViolation, BackendTimeout, BackendUnavailable,
    ReasoningBackendError)
from .openai_config import OpenAIConfig
from .openai_prompt_builder import build_openai_payload
from .openai_response_parser import parse_openai_response
from .openai_response_diagnostics import describe_response
from .safe_logging import log_backend_error, log_backend_outcome, log_response_diagnostic
from .token_policy import TokenPolicy
from .versions import OPENAI_BACKEND_VERSION
from dataclasses import replace


class OpenAIReasoningBackend:
    """Adaptador stateless de Responses API, sin tools ni acceso a evidencia cruda."""
    backend_name = "openai"
    backend_version = OPENAI_BACKEND_VERSION

    def __init__(self, config: OpenAIConfig | None = None, client=None) -> None:
        self.config = config or OpenAIConfig.from_env()
        self.model_name = self.config.model
        self._injected_client = client

    def _client(self):
        if self._injected_client is not None: return self._injected_client
        try:
            from openai import OpenAI
        except ImportError as error:
            raise BackendUnavailable("official openai SDK is not installed") from error
        return OpenAI(api_key=self.config.api_key, timeout=self.config.timeout_seconds, max_retries=0)

    def reason(self, request: ReasoningRequest) -> ReasoningResponse:
        input_token_estimate = None
        try:
            payload = build_openai_payload(request, self.config)
            input_token_estimate = TokenPolicy().enforce_openai_input(payload)
            response = self._client().responses.create(**payload)
            diagnostic = describe_response(response)
            log_response_diagnostic(diagnostic)
            parsed = parse_openai_response(response, request.request_id, self.backend_name, self.backend_version,
                self.model_name, diagnostic, request.context.reference_map, request.capabilities)
            metadata = replace(parsed.backend_metadata, input_token_estimate=input_token_estimate,
                input_token_estimation_error_percent=TokenPolicy.estimation_error_percent(
                    input_token_estimate.estimated_total_input_tokens, parsed.backend_metadata.input_token_count))
            parsed = replace(parsed, backend_metadata=metadata)
            log_backend_outcome(parsed.backend_metadata)
            return parsed
        except ReasoningBackendError as error:
            error.input_token_estimate = input_token_estimate
            log_backend_error(error)
            raise
        except Exception as error:
            mapped = self._map_provider_error(error)
            log_backend_error(mapped)
            raise mapped from error

    @staticmethod
    def _sanitize_message(error) -> str:
        text = str(error).replace("\n", " ").replace("\r", " ")[:500]
        return re.sub(r"(?i)(sk-[a-z0-9_-]+|bearer\s+\S+|api[_ -]?key\s*[:=]\s*\S+)", "<REDACTED>", text)

    def _map_provider_error(self, error):
        name = error.__class__.__name__
        status = getattr(error, "status_code", None) or getattr(error, "status", None)
        code, param = getattr(error, "code", None), getattr(error, "param", None)
        details = {"provider_error_type": name, "http_status": status, "provider_error_code": code,
            "provider_error_param": param, "technical_message": self._sanitize_message(error)}
        schema_rejected = status == 400 and (code in {"invalid_json_schema", "schema_validation_error"} or
            (isinstance(param, str) and ("schema" in param or "response_format" in param or "text.format" in param)))
        if schema_rejected:
            return BackendRequestSchemaViolation("provider rejected request schema", **details)
        if "Timeout" in name: return BackendTimeout("OpenAI request timed out", **details)
        if any(marker in name for marker in ("RateLimit", "Connection", "InternalServer", "APIStatus")):
            return BackendUnavailable(f"OpenAI provider error: {name}", **details)
        return BackendUnavailable(f"OpenAI request failed: {name}", **details)
