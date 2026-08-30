"""Índices deterministas que evitan comparaciones globales entre eventos."""

from collections import defaultdict
from typing import Callable, Hashable, Iterable

from soc_ai_agent.contracts.events import NormalizedEvent


def grouped(events: Iterable[NormalizedEvent], key_fn: Callable[[NormalizedEvent], Hashable | None],
            max_group_events: int) -> tuple[dict[Hashable, tuple[NormalizedEvent, ...]], tuple[str, ...]]:
    buckets: dict[Hashable, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        key = key_fn(event)
        if key is not None:
            buckets[key].append(event)
    accepted: dict[Hashable, tuple[NormalizedEvent, ...]] = {}
    diagnostics: list[str] = []
    for key, members in buckets.items():
        if len(members) > max_group_events:
            diagnostics.append(f"group_limit_exceeded:{repr(key)}:{len(members)}")
            continue
        accepted[key] = tuple(sorted(members, key=lambda event: event.event_uid))
    return accepted, tuple(diagnostics)
