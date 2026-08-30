from dataclasses import dataclass, replace
import time

from .contracts import BackendMetadata
from .contracts import ReasoningResponse
from .errors import BackendMalformedResponse, BackendTimeout, BackendUnavailable, ReasoningBackendError
from .token_policy import TokenPolicy


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 2
    timeout_seconds: float = 20.0
    max_total_seconds: float | None = None

    def execute(self, backend, request, token_policy: TokenPolicy):
        attempts = 0; last_error = None; started = time.monotonic()
        while attempts < self.max_attempts:
            if attempts and self.max_total_seconds is not None and time.monotonic() - started >= self.max_total_seconds:
                break
            attempts += 1
            try:
                response = backend.reason(request)
                if not isinstance(response, ReasoningResponse):
                    raise BackendMalformedResponse("backend did not return ReasoningResponse")
                token_policy.enforce_output(response, request.max_output_tokens)
                metadata = response.backend_metadata or BackendMetadata(backend.backend_name, backend.backend_version,
                    backend.model_name, request.request_id, None, None, None, None, 0, 0)
                metadata = replace(metadata, request_id=request.request_id, retry_count=attempts - 1,
                    attempt_count=attempts, latency_ms=int((time.monotonic() - started) * 1000),
                    timeout_seconds=self.timeout_seconds, max_total_seconds=self.max_total_seconds,
                    max_attempts=self.max_attempts)
                return response, metadata, None
            except (BackendTimeout, BackendUnavailable) as error:
                last_error = error
                if attempts >= self.max_attempts: break
            except ReasoningBackendError as error:
                last_error = error; break
        diagnostic = getattr(last_error, "backend_diagnostic", None)
        input_estimate = getattr(last_error, "input_token_estimate", None)
        metadata = BackendMetadata(backend.backend_name, backend.backend_version,
            getattr(diagnostic, "response_model", None) or backend.model_name, request.request_id,
            getattr(diagnostic, "provider_response_id", None),
            getattr(diagnostic, "input_tokens", None), getattr(diagnostic, "output_tokens", None),
            int((time.monotonic() - started) * 1000), max(0, attempts - 1), attempts,
            getattr(last_error, "response_status", None) or getattr(diagnostic, "response_status", None),
            getattr(last_error, "incomplete_reason", None) or getattr(diagnostic, "incomplete_reason", None),
            getattr(diagnostic, "reasoning_tokens", None), diagnostic, getattr(diagnostic, "provider_response_id", None),
            input_estimate, TokenPolicy.estimation_error_percent(getattr(input_estimate, "estimated_total_input_tokens", None),
            getattr(diagnostic, "input_tokens", None)), self.timeout_seconds, self.max_total_seconds, self.max_attempts)
        return None, metadata, last_error
