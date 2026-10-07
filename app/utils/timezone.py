"""
Honeypot Nexus - Central Timezone & Datetime Utilities
Source of Truth for timezone-aware handling, UTC storage, and Asia/Kolkata (IST) display conversion.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Optional, Union

UTC = timezone.utc
IST = ZoneInfo("Asia/Kolkata")


def now_utc() -> datetime:
    """Returns the current timezone-aware UTC datetime."""
    return datetime.now(UTC)


def to_utc(dt: Optional[Union[datetime, str]]) -> Optional[datetime]:
    """
    Ensures datetime is timezone-aware in UTC.
    If naive datetime is provided (e.g. from SQLite), treats it as UTC per architecture rules.
    If ISO string is provided, parses it safely as UTC.
    """
    if dt is None:
        return None

    if isinstance(dt, str):
        try:
            # Handle ISO string with Z or without timezone
            clean_str = dt.strip()
            if clean_str.endswith("Z"):
                clean_str = clean_str[:-1] + "+00:00"
            elif not ("+" in clean_str[-6:] or "-" in clean_str[-6:]):
                clean_str = clean_str.replace(" ", "T") + "+00:00"
            dt = datetime.fromisoformat(clean_str)
        except Exception:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)

    return dt


def to_ist(dt: Optional[Union[datetime, str]]) -> Optional[datetime]:
    """
    Converts a UTC or naive datetime to Asia/Kolkata (IST).
    """
    utc_dt = to_utc(dt)
    if utc_dt is None:
        return None
    return utc_dt.astimezone(IST)


def to_utc_iso(dt: Optional[Union[datetime, str]]) -> Optional[str]:
    """
    Returns a strict ISO 8601 UTC timestamp with +00:00 offset.
    Example: '2026-10-06T16:18:06.123456+00:00'
    """
    if dt is None:
        return None
    utc_dt = to_utc(dt)
    if utc_dt is None:
        return None
    return utc_dt.isoformat()


def format_ist(dt: Optional[Union[datetime, str]], fmt: str = "%d %b %Y, %I:%M:%S %p IST") -> str:
    """
    Converts datetime to Asia/Kolkata (IST) and formats according to the provided format string.
    """
    ist_dt = to_ist(dt)
    if ist_dt is None:
        return "--:--:--"
    return ist_dt.strftime(fmt)


def format_ist_time(dt: Optional[Union[datetime, str]]) -> str:
    """
    Formats datetime as time-only in Asia/Kolkata: '09:49:18 PM'.
    """
    return format_ist(dt, fmt="%I:%M:%S %p")


def format_ist_full(dt: Optional[Union[datetime, str]]) -> str:
    """
    Formats datetime as full date, time, and timezone in Asia/Kolkata:
    '06 Oct 2026, 09:49:18 PM IST'.
    """
    return format_ist(dt, fmt="%d %b %Y, %I:%M:%S %p IST")
