"""
Unit tests for Honeypot Nexus Timezone and Datetime Handling
Validates UTC internal storage and Asia/Kolkata (IST) display formatting.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import pytest

from app.utils.timezone import (
    now_utc,
    to_utc,
    to_ist,
    to_utc_iso,
    format_ist,
    format_ist_time,
    format_ist_full,
    UTC,
    IST
)


def test_now_utc():
    now = now_utc()
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc


def test_to_utc_naive_conversion():
    naive = datetime(2026, 10, 6, 16, 18, 6)
    utc = to_utc(naive)
    assert utc.tzinfo == timezone.utc
    assert utc.year == 2026
    assert utc.month == 10
    assert utc.day == 6
    assert utc.hour == 16
    assert utc.minute == 18
    assert utc.second == 6


def test_to_utc_iso_string():
    iso_z = "2026-10-06T16:18:06Z"
    utc = to_utc(iso_z)
    assert utc.tzinfo == timezone.utc
    assert utc.hour == 16
    assert utc.minute == 18

    iso_offset = "2026-10-06T21:48:06+05:30"
    utc2 = to_utc(iso_offset)
    assert utc2.tzinfo == timezone.utc
    assert utc2.hour == 16
    assert utc2.minute == 18


def test_to_ist_conversion():
    # 16:18:06 UTC is 21:48:06 IST (+05:30)
    utc_dt = datetime(2026, 10, 6, 16, 18, 6, tzinfo=timezone.utc)
    ist_dt = to_ist(utc_dt)
    assert ist_dt.tzinfo == ZoneInfo("Asia/Kolkata")
    assert ist_dt.hour == 21
    assert ist_dt.minute == 48
    assert ist_dt.second == 6
    assert ist_dt.day == 6


def test_format_ist_time():
    utc_dt = datetime(2026, 10, 6, 16, 18, 6, tzinfo=timezone.utc)
    formatted = format_ist_time(utc_dt)
    assert formatted == "09:48:06 PM"


def test_format_ist_full():
    utc_dt = datetime(2026, 10, 6, 16, 18, 6, tzinfo=timezone.utc)
    formatted = format_ist_full(utc_dt)
    assert formatted == "06 Oct 2026, 09:48:06 PM IST"


def test_to_utc_iso():
    naive = datetime(2026, 10, 6, 16, 18, 6)
    iso_str = to_utc_iso(naive)
    assert iso_str == "2026-10-06T16:18:06+00:00"
