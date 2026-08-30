from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Any


PLACEHOLDERS = {"-", "NOT_TRANSLATED", "Unavailable", "N/A"}


def scalar(value: Any, warnings: list[str], field_name: str) -> str | None:
    """Devuelve sólo valores escalares aprovechables, sin inventar de listas ambiguas."""
    if isinstance(value, list):
        if any(isinstance(item, str) and item in PLACEHOLDERS for item in value):
            warnings.append(f"source_placeholder:{field_name}")
        usable = [item for item in value if isinstance(item, str) and item not in PLACEHOLDERS and item != ""]
        if len(usable) == 1:
            return usable[0]
        if usable:
            warnings.append(f"ambiguous_multivalue:{field_name}")
        return None
    if value is None or value == "":
        return None
    if isinstance(value, str) and value in PLACEHOLDERS:
        warnings.append(f"source_placeholder:{field_name}")
        return None
    return str(value)


def optional_int(value: Any, warnings: list[str], field_name: str) -> int | None:
    text = scalar(value, warnings, field_name)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        warnings.append(f"invalid_integer:{field_name}")
        return None


def valid_ip(value: Any, warnings: list[str], field_name: str) -> str | None:
    text = scalar(value, warnings, field_name)
    if text is None:
        return None
    try:
        ip_address(text)
    except ValueError:
        warnings.append(f"invalid_ip:{field_name}")
        return None
    return text


def payload_of(parsed: object) -> dict[str, Any]:
    if isinstance(parsed, dict) and isinstance(parsed.get("result"), dict):
        return parsed["result"]
    return parsed if isinstance(parsed, dict) else {}


def split_user(value: Any, warnings: list[str], field_name: str) -> tuple[str | None, str | None]:
    text = scalar(value, warnings, field_name)
    if text is None:
        return None, None
    if "\\" in text:
        domain, name = text.split("\\", 1)
        return name or None, domain or None
    return text, None


def parse_hashes(value: Any, warnings: list[str]) -> dict[str, str]:
    text = scalar(value, warnings, "Hashes")
    if text is None:
        return {}
    hashes: dict[str, str] = {}
    for part in text.split(","):
        if "=" not in part:
            warnings.append("invalid_hashes")
            continue
        algorithm, digest = part.split("=", 1)
        if algorithm and digest:
            hashes[algorithm.lower()] = digest
        else:
            warnings.append("invalid_hashes")
    return hashes


def utc_time(value: Any, warnings: list[str]) -> str | None:
    """Acepta el formato Sysmon UTC sólo tras verificar que es una fecha válida."""
    text = scalar(value, warnings, "UtcTime")
    if text is None:
        return None
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        warnings.append("invalid_timestamp:UtcTime")
        return None
    return text
