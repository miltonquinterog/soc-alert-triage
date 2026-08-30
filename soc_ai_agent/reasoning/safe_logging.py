import logging


LOGGER = logging.getLogger("soc_ai_agent.reasoning.openai")


def log_backend_outcome(metadata, error_code=None):
    """Sólo metadatos operativos; nunca prompts, evidencia ni secretos."""
    LOGGER.info("reasoning_backend_outcome backend=%s request_id=%s provider_request_id=%s status=%s retries=%s attempts=%s error=%s",
        metadata.backend_name, metadata.request_id, metadata.provider_request_id, metadata.response_status,
        metadata.retry_count, metadata.attempt_count, error_code)


def log_backend_error(error):
    """Diagnóstico técnico sanitizado, sin payload ni credenciales."""
    LOGGER.warning("reasoning_backend_error type=%s http_status=%s code=%s param=%s message=%s",
        error.provider_error_type, error.http_status, error.provider_error_code, error.provider_error_param,
        error.technical_message)
    diagnostic = getattr(error, "response_diagnostic", None)
    if diagnostic:
        log_response_diagnostic(diagnostic, getattr(error, "failure_stage", None), error)


def log_response_diagnostic(diagnostic, failure_stage=None, error=None):
    """No incluye output_text, prompts, evidencia ni valores generados."""
    items = tuple((item.type, item.status, item.role, item.content_types) for item in diagnostic.output_items)
    LOGGER.info("openai_response_structure id=%s status=%s incomplete_reason=%s error_code=%s error_message=%s "
        "model=%s input_tokens=%s output_tokens=%s reasoning_tokens=%s output_count=%s output_types=%s "
        "output_items=%s output_text_present=%s output_text_length=%s output_text_sha256=%s failure_stage=%s "
        "validation_path=%s schema_rule=%s expected_type=%s received_type=%s",
        diagnostic.response_id, diagnostic.status, diagnostic.incomplete_reason, diagnostic.error_code,
        diagnostic.error_message, diagnostic.model, diagnostic.input_tokens, diagnostic.output_tokens,
        diagnostic.reasoning_tokens, diagnostic.output_count, diagnostic.output_types, items,
        diagnostic.output_text_present, diagnostic.output_text_length, diagnostic.output_text_sha256,
        failure_stage, getattr(error, "validation_path", None), getattr(error, "schema_rule", None),
        getattr(error, "expected_type", None), getattr(error, "received_type", None))
