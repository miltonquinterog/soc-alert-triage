"""Validación estructural básica; no clasifica ni infiere actividad."""

from soc_ai_agent.contracts.events import NormalizedEvent, SCHEMA_VERSION, make_event_uid


def validate_event(event: NormalizedEvent) -> tuple[str, ...]:
    errors: list[str] = []
    if event.schema_version != SCHEMA_VERSION: errors.append("unsupported_schema_version")
    if not event.raw_event: errors.append("missing_raw_event")
    expected = make_event_uid(event.dataset.name, event.dataset.line_number, event.raw_event)
    if event.event_uid != expected: errors.append("event_uid_not_reproducible")
    if event.dataset.format != "jsonl": errors.append("unsupported_dataset_format")
    if not event.source.platform: errors.append("missing_source_platform")
    return tuple(errors)
