"""Unit tests for the Open DMR Terminal Protocol receive path.

No network access is required: every test works on bytes.
"""

import hashlib
import struct

import pytest

from odtp import (
    SERVICE_OPEN_TERMINAL,
    TYPE_AUTHENTICATION,
    TYPE_CHALLENGE,
    TYPE_CLOSE,
    TYPE_KEEP_ALIVE,
    TYPE_MESSAGE_STATUS,
    TYPE_MESSAGE_TEXT,
    TYPE_REPORT,
    OdtpReceiver,
    OdtpProtocolError,
    auth_digest,
    pack_authentication,
    pack_header,
    pack_keep_alive,
    parse_header,
    parse_message_status,
    parse_message_text,
)


# --- header ---------------------------------------------------------------


def test_header_is_eighteen_bytes_with_rewind_signature():
    packet = pack_header(TYPE_KEEP_ALIVE, flags=0, number=7, length=3)
    assert len(packet) == 18
    assert packet[:8] == b"REWIND01"
    # little-endian throughout
    assert struct.unpack("<HHIH", packet[8:]) == (TYPE_KEEP_ALIVE, 0, 7, 3)


def test_header_round_trips():
    header = parse_header(pack_header(TYPE_MESSAGE_TEXT, flags=1, number=0xDEADBEEF, length=42))
    assert header.type == TYPE_MESSAGE_TEXT
    assert header.flags == 1
    assert header.number == 0xDEADBEEF
    assert header.length == 42


def test_parse_header_rejects_wrong_signature():
    packet = bytearray(pack_header(TYPE_KEEP_ALIVE))
    packet[0:8] = b"REWIND02"
    with pytest.raises(OdtpProtocolError):
        parse_header(bytes(packet))


def test_parse_header_rejects_short_packet():
    with pytest.raises(OdtpProtocolError):
        parse_header(b"REWIND01\x00\x00")


# --- keep-alive -----------------------------------------------------------


def test_keep_alive_carries_dmr_id_service_and_description():
    packet = pack_keep_alive(2140410, description="spike/0.1")
    header = parse_header(packet)
    assert header.type == TYPE_KEEP_ALIVE

    payload = packet[18:]
    assert header.length == len(payload)

    dmr_id, service = struct.unpack("<IB", payload[:5])
    assert dmr_id == 2140410
    assert service == SERVICE_OPEN_TERMINAL == 0x21
    assert payload[5:] == b"spike/0.1\x00"


# --- authentication -------------------------------------------------------


def test_auth_digest_is_sha256_of_salt_then_password():
    salt = bytes.fromhex("7f4d255f")
    assert auth_digest(salt, "hunter2") == hashlib.sha256(salt + b"hunter2").digest()


def test_auth_digest_is_32_bytes_and_password_order_matters():
    salt = b"\x01\x02\x03\x04"
    digest = auth_digest(salt, "pw")
    assert len(digest) == 32
    assert digest != hashlib.sha256(b"pw" + salt).digest()


def test_pack_authentication_wraps_digest_in_header():
    packet = pack_authentication(b"\xaa\xbb\xcc\xdd", "pw")
    header = parse_header(packet)
    assert header.type == TYPE_AUTHENTICATION
    assert header.length == 32
    assert packet[18:] == auth_digest(b"\xaa\xbb\xcc\xdd", "pw")


# --- message text ---------------------------------------------------------


def _text_payload(source_id, destination_id, option, text):
    encoded = text.encode("utf-16-le")
    return struct.pack("<IIIHH", 0, source_id, destination_id, option, len(encoded)) + encoded


def test_parse_message_text_private():
    message = parse_message_text(_text_payload(2140410, 2141168, 0x00, "Hola"))
    assert message.source_id == 2140410
    assert message.destination_id == 2141168
    assert message.option == 0x00
    assert message.is_group is False
    assert message.text == "Hola"


def test_parse_message_text_group_destination():
    message = parse_message_text(_text_payload(2140410, 91, 0x80, "grupo"))
    assert message.is_group is True
    assert message.destination_id == 91


def test_parse_message_text_handles_undocumented_option_seen_in_the_wild():
    """Master 2141 sent a private message with option 0x40, not 0x00.

    Observed 2026-11-10 from DMR ID 214999 to 2140410. The spec documents only
    0 (private) and 128 (group); real traffic uses 0x40 for private too, so
    classification must key on the 0x80 bit alone.
    """
    message = parse_message_text(_text_payload(214999, 2140410, 0x40, "EA7KLK-0 hi"))
    assert message.option == 0x40
    assert message.is_group is False
    assert message.text == "EA7KLK-0 hi"


def test_parse_message_text_preserves_non_ascii():
    message = parse_message_text(_text_payload(1, 2, 0, "Ñandú ✓"))
    assert message.text == "Ñandú ✓"


def test_parse_message_text_rejects_odd_byte_length():
    payload = struct.pack("<IIIHH", 0, 1, 2, 0, 3) + b"abc"
    with pytest.raises(OdtpProtocolError):
        parse_message_text(payload)


def test_parse_message_text_rejects_truncated_payload():
    with pytest.raises(OdtpProtocolError):
        parse_message_text(struct.pack("<III", 0, 1, 2))


def test_parse_message_text_rejects_declared_length_past_end():
    encoded = "hi".encode("utf-16-le")
    payload = struct.pack("<IIIHH", 0, 1, 2, 0, len(encoded) + 20) + encoded
    with pytest.raises(OdtpProtocolError):
        parse_message_text(payload)


# --- message status -------------------------------------------------------


def test_parse_message_status_success():
    payload = struct.pack("<IIIB", 0, 2141168, 2140410, 0x08)
    status = parse_message_status(payload)
    assert status.source_id == 2141168
    assert status.destination_id == 2140410
    assert status.status == 0x08
    assert status.succeeded is True


def test_parse_message_status_failure():
    status = parse_message_status(struct.pack("<IIIB", 0, 1, 2, 0x40))
    assert status.succeeded is False


# --- receiver state machine ----------------------------------------------


class Recorder:
    def __init__(self):
        self.messages = []
        self.statuses = []
        self.reports = []
        self.closed = False

    def on_message(self, message):
        self.messages.append(message)

    def on_status(self, status):
        self.statuses.append(status)

    def on_report(self, text):
        self.reports.append(text)

    def on_close(self):
        self.closed = True


def _challenge(salt=b"\xde\xad\xbe\xef"):
    return pack_header(TYPE_CHALLENGE, number=0, length=len(salt)) + salt


def _server_keep_alive():
    return pack_header(TYPE_KEEP_ALIVE, number=0, length=0)


def _receiver(recorder, password="pw"):
    return OdtpReceiver(
        dmr_id=2140410,
        password=password,
        on_message=recorder.on_message,
        on_status=recorder.on_status,
        on_report=recorder.on_report,
        on_close=recorder.on_close,
    )


def test_receiver_answers_challenge_with_digest():
    recorder = Recorder()
    receiver = _receiver(recorder)

    outbound = receiver.handle(_challenge(b"\xde\xad\xbe\xef"))

    assert len(outbound) == 1
    header = parse_header(outbound[0])
    assert header.type == TYPE_AUTHENTICATION
    assert outbound[0][18:] == hashlib.sha256(b"\xde\xad\xbe\xef" + b"pw").digest()
    assert receiver.authenticated is False


def test_receiver_marks_authenticated_on_server_keep_alive():
    recorder = Recorder()
    receiver = _receiver(recorder)

    receiver.handle(_challenge())
    assert receiver.authenticated is False

    outbound = receiver.handle(_server_keep_alive())
    assert outbound == []
    assert receiver.authenticated is True


def test_receiver_does_not_reanswer_challenge_after_auth():
    recorder = Recorder()
    receiver = _receiver(recorder)
    receiver.handle(_challenge())
    receiver.handle(_server_keep_alive())

    assert receiver.handle(_challenge(b"\x11\x22\x33\x44")) == []


def test_receiver_delivers_private_message_text():
    recorder = Recorder()
    receiver = _receiver(recorder)
    receiver.handle(_challenge())
    receiver.handle(_server_keep_alive())

    payload = _text_payload(2141168, 2140410, 0x00, "prueba")
    receiver.handle(pack_header(TYPE_MESSAGE_TEXT, length=len(payload)) + payload)

    assert len(recorder.messages) == 1
    assert recorder.messages[0].text == "prueba"
    assert recorder.messages[0].source_id == 2141168


def test_receiver_delivers_status_without_crashing():
    recorder = Recorder()
    receiver = _receiver(recorder)
    receiver.handle(_challenge())
    receiver.handle(_server_keep_alive())

    payload = struct.pack("<IIIB", 0, 2140410, 2141168, 0x08)
    receiver.handle(pack_header(TYPE_MESSAGE_STATUS, length=len(payload)) + payload)

    assert len(recorder.statuses) == 1
    assert recorder.statuses[0].succeeded is True


def test_receiver_surfaces_server_report_text():
    recorder = Recorder()
    receiver = _receiver(recorder)
    receiver.handle(_challenge())
    receiver.handle(_server_keep_alive())

    report = b"Welcome EA7KLK"
    receiver.handle(pack_header(TYPE_REPORT, length=len(report)) + report)

    assert recorder.reports == ["Welcome EA7KLK"]


def test_receiver_handles_close():
    recorder = Recorder()
    receiver = _receiver(recorder)
    receiver.handle(_challenge())
    receiver.handle(_server_keep_alive())

    assert receiver.handle(pack_header(TYPE_CLOSE)) == []
    assert recorder.closed is True


def test_receiver_ignores_garbage_without_raising():
    recorder = Recorder()
    receiver = _receiver(recorder)

    outbound = receiver.handle(b"\x00" * 40)

    assert outbound == []
    assert receiver.authenticated is False


def test_receiver_survives_truncated_message_text():
    recorder = Recorder()
    receiver = _receiver(recorder)
    receiver.handle(_challenge())
    receiver.handle(_server_keep_alive())

    payload = struct.pack("<IIIHH", 0, 1, 2, 0, 4) + b"ab"
    receiver.handle(pack_header(TYPE_MESSAGE_TEXT, length=len(payload)) + payload)

    assert recorder.messages == []
    assert receiver.errors == 1


def test_keep_alive_packet_uses_incrementing_sequence():
    recorder = Recorder()
    receiver = _receiver(recorder)

    first = parse_header(receiver.keep_alive_packet())
    second = parse_header(receiver.keep_alive_packet())

    assert second.number == first.number + 1
