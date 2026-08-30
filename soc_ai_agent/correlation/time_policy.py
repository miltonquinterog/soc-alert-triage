"""Tiempo conservador: sólo event_time UTC válido cuenta para una ventana fuerte."""

from __future__ import annotations

from datetime import datetime

from soc_ai_agent.contracts.events import NormalizedEvent
from .contracts import TimeWindow


AUTH_WINDOW_SECONDS = 15 * 60
TEMPORAL_WINDOW_SECONDS = 5 * 60


def usable_event_time(event: NormalizedEvent) -> datetime | None:
    if event.time.timezone_status != "utc" or not event.time.event_time:
        return None
    try:
        return datetime.fromisoformat(event.time.event_time.replace("Z", "+00:00"))
    except ValueError:
        return None


def window_between(source: NormalizedEvent, destination: NormalizedEvent, max_seconds: int,
                   policy_name: str) -> TimeWindow | None:
    source_time = usable_event_time(source)
    destination_time = usable_event_time(destination)
    if source_time is None or destination_time is None:
        return None
    delta = abs((destination_time - source_time).total_seconds())
    if delta > max_seconds:
        return None
    return TimeWindow(source_time=source.time.event_time, destination_time=destination.time.event_time,
                      delta_seconds=delta, policy_name=policy_name)
