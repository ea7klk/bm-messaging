"""Minimal receive-only client for the BrandMeister Open DMR Terminal Protocol.

Scope: authenticate as one DMR ID, keep the link alive, and surface inbound
SMS (REWIND_TYPE_MESSAGE_TEXT) plus delivery reports. No audio, no RF, no codec.

Wire format is the Rewind protocol: little-endian, 18-byte header.
Spec: https://wiki.brandmeister.network/index.php/Open_DMR_Terminal_Protocol
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Callable

SIGN = b"REWIND01"
HEADER_SIZE = 18

# REWIND_CLASS_REWIND_CONTROL
TYPE_KEEP_ALIVE = 0x0000
TYPE_CLOSE = 0x0001
TYPE_CHALLENGE = 0x0002
TYPE_AUTHENTICATION = 0x0003

# REWIND_CLASS_SYSTEM_CONSOLE
TYPE_REPORT = 0x0200

# REWIND_CLASS_APPLICATION
TYPE_SUBSCRIPTION = 0x0901
TYPE_CANCELLING = 0x0902
TYPE_DMR_DATA_BASE = 0x0910
TYPE_DMR_AUDIO_FRAME = 0x0920

# REWIND_CLASS_TERMINAL
TYPE_TERMINAL_IDLE = 0x0A00
TYPE_MESSAGE_TEXT = 0x0A10
TYPE_MESSAGE_STATUS = 0x0A11

# REWIND_SERVICE_OPEN_TERMINAL (REWIND_ROLE_APPLICATION + 1)
SERVICE_OPEN_TERMINAL = 0x21

# RewindTextMessageData.option
OPTION_PRIVATE = 0x0000
OPTION_GROUP = 0x0080

# DMR Data Call Report status octet: 0b00001000 is success
STATUS_SUCCESS = 0x08


class OdtpProtocolError(ValueError):
    """Raised when a datagram does not match the Rewind wire format."""


@dataclass(frozen=True)
class Header:
    type: int
    flags: int
    number: int
    length: int


@dataclass(frozen=True)
class TextMessage:
    source_id: int
    destination_id: int
    option: int
    text: str

    @property
    def is_group(self) -> bool:
        return bool(self.option & OPTION_GROUP)


@dataclass(frozen=True)
class MessageStatus:
    source_id: int
    destination_id: int
    status: int

    @property
    def succeeded(self) -> bool:
        return self.status == STATUS_SUCCESS


# --- encoding -------------------------------------------------------------


def pack_header(type_: int, flags: int = 0, number: int = 0, length: int = 0) -> bytes:
    return SIGN + struct.pack("<HHIH", type_, flags, number, length)


def parse_header(data: bytes) -> Header:
    if len(data) < HEADER_SIZE:
        raise OdtpProtocolError(f"short packet: {len(data)} bytes")
    if data[:8] != SIGN:
        raise OdtpProtocolError(f"bad signature: {data[:8]!r}")
    type_, flags, number, length = struct.unpack("<HHIH", data[8:HEADER_SIZE])
    return Header(type=type_, flags=flags, number=number, length=length)


def pack_keep_alive(
    dmr_id: int,
    number: int = 0,
    description: str = "bm-messaging-spike/0.1",
    service: int = SERVICE_OPEN_TERMINAL,
) -> bytes:
    """Keep-alive doubles as connection establishment (RewindVersionData)."""
    payload = struct.pack("<IB", dmr_id, service) + description.encode("utf-8") + b"\x00"
    return pack_header(TYPE_KEEP_ALIVE, number=number, length=len(payload)) + payload


def auth_digest(salt: bytes, password: str) -> bytes:
    """SHA-256 over the server salt followed by the account password."""
    return hashlib.sha256(salt + password.encode("utf-8")).digest()


def pack_authentication(salt: bytes, password: str, number: int = 0) -> bytes:
    digest = auth_digest(salt, password)
    return pack_header(TYPE_AUTHENTICATION, number=number, length=len(digest)) + digest


def pack_subscription(session_type: int, number_: int, number: int = 0) -> bytes:
    payload = struct.pack("<II", session_type, number_)
    return pack_header(TYPE_SUBSCRIPTION, number=number, length=len(payload)) + payload


# --- decoding -------------------------------------------------------------


def parse_message_text(payload: bytes) -> TextMessage:
    """Decode RewindTextMessageData: reserved, source, dest, option, length, UTF-16LE."""
    if len(payload) < 16:
        raise OdtpProtocolError(f"short text payload: {len(payload)} bytes")
    _reserved, source_id, destination_id, option, declared = struct.unpack("<IIIHH", payload[:16])
    body = payload[16:]
    if declared % 2:
        raise OdtpProtocolError(f"odd UTF-16LE byte length: {declared}")
    if declared > len(body):
        raise OdtpProtocolError(f"declared {declared} bytes, only {len(body)} present")
    return TextMessage(
        source_id=source_id,
        destination_id=destination_id,
        option=option,
        text=body[:declared].decode("utf-16-le", errors="replace"),
    )


def parse_message_status(payload: bytes) -> MessageStatus:
    if len(payload) < 13:
        raise OdtpProtocolError(f"short status payload: {len(payload)} bytes")
    _reserved, source_id, destination_id, status = struct.unpack("<IIIB", payload[:13])
    return MessageStatus(source_id=source_id, destination_id=destination_id, status=status)


# --- state machine --------------------------------------------------------


class OdtpReceiver:
    """Drives one terminal connection, one DMR ID.

    ``handle`` is pure with respect to I/O: give it a datagram, it returns the
    datagrams that should be sent back. That keeps the protocol testable without
    a socket, and keeps the send loop in the caller.
    """

    def __init__(
        self,
        dmr_id: int,
        password: str,
        on_message: Callable[[TextMessage], None],
        on_status: Callable[[MessageStatus], None] | None = None,
        on_report: Callable[[str], None] | None = None,
        on_close: Callable[[], None] | None = None,
        description: str = "bm-messaging-spike/0.1",
    ) -> None:
        self.dmr_id = dmr_id
        self._password = password
        self._on_message = on_message
        self._on_status = on_status
        self._on_report = on_report
        self._on_close = on_close
        self._description = description

        self.authenticated = False
        self.errors = 0
        self._seq = 0

    # -- outbound --

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return self._seq

    def keep_alive_packet(self) -> bytes:
        return pack_keep_alive(self.dmr_id, number=self._next_seq(), description=self._description)

    # -- inbound --

    def handle(self, data: bytes) -> list[bytes]:
        try:
            header = parse_header(data)
        except OdtpProtocolError:
            self.errors += 1
            return []

        payload = data[HEADER_SIZE:HEADER_SIZE + header.length]

        if header.type == TYPE_CHALLENGE:
            if self.authenticated:
                return []
            return [pack_authentication(payload, self._password, number=self._next_seq())]

        if header.type == TYPE_KEEP_ALIVE:
            # The server acknowledges a successful authentication with an empty
            # keep-alive. It also echoes routine keep-alives.
            if not self.authenticated and header.length == 0:
                self.authenticated = True
            return []

        if header.type == TYPE_MESSAGE_TEXT:
            try:
                self._on_message(parse_message_text(payload))
            except OdtpProtocolError:
                self.errors += 1
            return []

        if header.type == TYPE_MESSAGE_STATUS:
            try:
                status = parse_message_status(payload)
            except OdtpProtocolError:
                self.errors += 1
                return []
            if self._on_status is not None:
                self._on_status(status)
            return []

        if header.type == TYPE_REPORT:
            if self._on_report is not None:
                self._on_report(payload.rstrip(b"\x00").decode("utf-8", errors="replace"))
            return []

        if header.type == TYPE_CLOSE:
            if self._on_close is not None:
                self._on_close()
            return []

        return []
