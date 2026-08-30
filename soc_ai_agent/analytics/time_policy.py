from datetime import datetime, timezone

from soc_ai_agent.contracts.events import NormalizedEvent


AUTH_WINDOW_SECONDS = 15 * 60


def usable_time(event: NormalizedEvent) -> datetime | None:
    if event.time.timezone_status != "utc" or not event.time.event_time:
        return None
    try:
        parsed = datetime.fromisoformat(event.time.event_time.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None
