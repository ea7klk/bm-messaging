"""Tests for the receipt metadata report."""

import struct
from datetime import datetime, timedelta, timezone

import pytest

from odtp import TextMessage, parse_message_text
from receive import FrameMeta, format_report


def _meta(**overrides):
    observed = datetime(2026, 11, 10, 15, 33, 3, 412000, tzinfo=timezone.utc)
    connected = observed - timedelta(seconds=7, milliseconds=400)
    authed = connected + timedelta(milliseconds=200)
    message = TextMessage(
        source_id=214999,
        destination_id=2140410,
        option=0x0040,
        text="EA7KLK-0 Third test message from BBS",
    )
    base = dict(
        observed_at=observed,
        connected_at=connected,
        authenticated_at=authed,
        master="84.232.5.113",
        port=54006,
        dmr_id=2140410,
        frame_index=7,
        type=0x0A10,
        flags=0,
        number=3,
        declared_length=88,
        payload_length=88,
        message=message,
        raw_payload=bytes.fromhex("0000") * 44,
        keep_alives_sent=2,
        undecodable=1,
    )
    base.update(overrides)
    return FrameMeta(**base)


def test_report_contains_the_message_text():
    assert "EA7KLK-0 Third test message from BBS" in format_report(_meta())


def test_report_contains_identity_and_route():
    report = format_report(_meta())
    assert "2140410" in report  # terminal identity
    assert "214999" in report  # source
    assert "84.232.5.113" in report
    assert "54006" in report


def test_report_shows_option_in_hex_and_decimal():
    report = format_report(_meta())
    assert "0x0040" in report
    assert "64" in report


def test_report_shows_private_classification_for_option_0x40():
    assert "private" in format_report(_meta()).lower()


def test_report_classifies_group_when_group_bit_set():
    message = TextMessage(source_id=1, destination_id=91, option=0x0080, text="x")
    report = format_report(_meta(message=message))
    assert "group" in report.lower()


def test_report_shows_header_fields():
    report = format_report(_meta())
    assert "0x0a10" in report.lower()
    assert "flags" in report.lower()
    assert "seq" in report.lower()


def test_report_shows_byte_and_char_lengths():
    report = format_report(_meta())
    text = "EA7KLK-0 Third test message from BBS"
    assert str(len(text.encode("utf-16-le"))) in report
    assert str(len(text)) in report


def test_report_includes_raw_payload_hex():
    meta = _meta(raw_payload=b"\xde\xad\xbe\xef")
    assert "deadbeef" in format_report(meta)


def test_report_shows_timing_relative_to_connect():
    report = format_report(_meta())
    assert "2026-11-10T15:33:03.412" in report
    assert "7.4" in report  # seconds since connect


def test_report_handles_unauthenticated_meta():
    report = format_report(_meta(authenticated_at=None))
    assert "never" in report.lower() or "n/a" in report.lower()


def test_report_survives_non_ascii_text():
    message = TextMessage(source_id=1, destination_id=2, option=0, text="Ñandú ✓")
    assert "Ñandú ✓" in format_report(_meta(message=message))


def test_report_decodes_the_live_payload_shape():
    """Build metadata from a real observed frame and check the round trip."""
    payload = (
        struct.pack("<IIIHH", 0, 214999, 2140410, 0x0040, 72)
        + "EA7KLK-0 Third test message from BBS".encode("utf-16-le")
    )
    message = parse_message_text(payload)
    report = format_report(_meta(message=message, raw_payload=payload, declared_length=len(payload)))
    assert "EA7KLK-0 Third test message from BBS" in report
    assert "0x0040" in report
    assert payload.hex()[:32] in report
