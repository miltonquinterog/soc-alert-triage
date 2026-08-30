from collections import defaultdict
from typing import Iterable

from soc_ai_agent.contracts.events import NormalizedEvent


def authentication_groups(events: Iterable[NormalizedEvent], platform: str):
    groups: dict[tuple[str, str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.source.platform != platform:
            continue
        user, host, source_ip = event.correlation.user, event.correlation.host, event.correlation.source_ip
        if user and host and source_ip:
            groups[(user, host, source_ip)].append(event)
    return {key: tuple(sorted(value, key=lambda item: (item.time.event_time or "", item.event_uid)))
            for key, value in groups.items()}
