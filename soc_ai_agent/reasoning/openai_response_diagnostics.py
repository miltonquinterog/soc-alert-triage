"""Diagnóstico estructural de Responses sin registrar salida generada."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re


def _sanitize_message(value) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\n", " ").replace("\r", " ")[:500]
    return re.sub(r"(?i)(sk-[a-z0-9_-]+|bearer\s+\S+|api[_ -]?key\s*[:=]\s*\S+)", "<REDACTED>", text)


@dataclass(frozen=True)
class OutputItemDiagnostic:
    type: str | None
    status: str | None
    role: str | None
    content_types: tuple[str | None, ...]


@dataclass(frozen=True)
class ResponseStructuralDiagnostic:
    response_id: str | None
    status: str | None
    incomplete_reason: str | None
    error_code: str | None
    error_message: str | None
    model: str | None
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    output_count: int
    output_types: tuple[str | None, ...]
    output_items: tuple[OutputItemDiagnostic, ...]
    output_text_present: bool
    output_text_length: int | None
    output_text_sha256: str | None


@dataclass(frozen=True)
class BackendDiagnostic:
    """Proyección transportable y segura de un fallo posterior a una Response."""
    provider_response_id: str | None
    response_status: str | None
    incomplete_reason: str | None
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    response_model: str | None
    output_types: tuple[str | None, ...]
    output_text_present: bool
    output_text_length: int | None
    output_text_sha256: str | None
    failure_stage: str | None
    validation_path: str | None
    schema_rule: str | None
    expected_type: str | None
    received_type: str | None


def describe_response(response) -> ResponseStructuralDiagnostic:
    """Extrae forma y metadatos; el texto nunca sale de esta función."""
    output = tuple(getattr(response, "output", None) or ())
    items = tuple(OutputItemDiagnostic(getattr(item, "type", None), getattr(item, "status", None),
        getattr(item, "role", None), tuple(getattr(content, "type", None) for content in (getattr(item, "content", None) or ())))
        for item in output)
    output_text = getattr(response, "output_text", None)
    present = isinstance(output_text, str)
    details = getattr(getattr(response, "usage", None), "output_tokens_details", None)
    error = getattr(response, "error", None)
    return ResponseStructuralDiagnostic(
        getattr(response, "id", None), getattr(response, "status", None),
        getattr(getattr(response, "incomplete_details", None), "reason", None),
        getattr(error, "code", None), _sanitize_message(getattr(error, "message", None)), getattr(response, "model", None),
        getattr(getattr(response, "usage", None), "input_tokens", None),
        getattr(getattr(response, "usage", None), "output_tokens", None),
        getattr(details, "reasoning_tokens", None), len(output), tuple(item.type for item in items), items,
        present, len(output_text) if present else None,
        sha256(output_text.encode("utf-8")).hexdigest() if present else None)


def make_backend_diagnostic(response: ResponseStructuralDiagnostic, error) -> BackendDiagnostic:
    """No transfiere texto generado ni mensajes de evidencia desde la Response."""
    return BackendDiagnostic(response.response_id, response.status, response.incomplete_reason,
        response.input_tokens, response.output_tokens, response.reasoning_tokens, response.model,
        response.output_types, response.output_text_present, response.output_text_length,
        response.output_text_sha256, getattr(error, "failure_stage", None),
        getattr(error, "validation_path", None), getattr(error, "schema_rule", None),
        getattr(error, "expected_type", None), getattr(error, "received_type", None))
