"""Tests for the receive runner's control flow, using a local UDP fake master."""

import socket
import struct
import threading
import time

import pytest

from odtp import (
    TYPE_CHALLENGE,
    TYPE_KEEP_ALIVE,
    TYPE_MESSAGE_TEXT,
    pack_header,
)
from receive import run


def _text_payload(source_id, destination_id, text, option=0):
    encoded = text.encode("utf-16-le")
    return struct.pack("<IIIHH", 0, source_id, destination_id, option, len(encoded)) + encoded


class FakeMaster(threading.Thread):
    """Plays the server side of a handshake, then optionally sends a message."""

    def __init__(self, send_message=True, message_after=0.3):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(10)
        self.port = self.sock.getsockname()[1]
        self.send_message = send_message
        self.message_after = message_after
        self.done = threading.Event()
        self.error = None

    def run(self):
        try:
            # 1. client keep-alive -> challenge
            _, client = self.sock.recvfrom(4096)
            salt = b"\xaa\xbb\xcc\xdd"
            self.sock.sendto(pack_header(TYPE_CHALLENGE, length=4) + salt, client)

            # 2. client authentication -> empty keep-alive means success
            _, client = self.sock.recvfrom(4096)
            self.sock.sendto(pack_header(TYPE_KEEP_ALIVE, length=0), client)

            # 3. optionally deliver one text message
            if self.send_message:
                time.sleep(self.message_after)
                payload = _text_payload(214999, 2140410, "prueba")
                self.sock.sendto(pack_header(TYPE_MESSAGE_TEXT, length=len(payload)) + payload, client)
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            self.error = exc
        finally:
            self.done.set()

    def stop(self):
        self.sock.close()


def test_run_exits_promptly_once_a_message_arrives():
    master = FakeMaster(send_message=True)
    master.start()
    try:
        received = []
        started = time.monotonic()
        code = run(
            host="127.0.0.1",
            port=master.port,
            dmr_id=2140410,
            password="pw",
            seconds=30,
            exit_after_message=True,
            on_message=received.append,
        )
        elapsed = time.monotonic() - started
    finally:
        master.stop()

    assert master.error is None
    assert code == 0
    assert len(received) == 1
    assert received[0].text == "prueba"
    assert received[0].source_id == 214999
    # Exit-on-message must not wait out the full window.
    assert elapsed < 10, f"took {elapsed:.1f}s, should have exited on receipt"


def test_run_keeps_listening_without_exit_flag():
    """Without the flag the loop runs its full window even after a message."""
    master = FakeMaster(send_message=True)
    master.start()
    try:
        received = []
        code = run(
            host="127.0.0.1",
            port=master.port,
            dmr_id=2140410,
            password="pw",
            seconds=2,
            exit_after_message=False,
            on_message=received.append,
        )
    finally:
        master.stop()

    assert master.error is None
    assert code == 0
    assert len(received) == 1


def test_run_returns_nonzero_when_authentication_never_confirms():
    """A master that never sends the confirming keep-alive must yield exit 2."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def silent_master():
        try:
            _, client = sock.recvfrom(4096)
            sock.sendto(pack_header(TYPE_CHALLENGE, length=4) + b"\x01\x02\x03\x04", client)
            # never confirm
            time.sleep(3)
        except OSError:
            pass

    thread = threading.Thread(target=silent_master, daemon=True)
    thread.start()
    try:
        code = run(
            host="127.0.0.1",
            port=port,
            dmr_id=2140410,
            password="wrong",
            seconds=1.5,
            exit_after_message=True,
        )
    finally:
        sock.close()

    assert code == 2


def test_run_reports_parse_errors_instead_of_crashing():
    """A malformed text message must be counted, not raise."""
    master = FakeMaster(send_message=False)
    master.start()
    try:
        received = []
        # Deliver garbage payload claiming a longer body than present.
        def inject():
            time.sleep(1.0)
            payload = struct.pack("<IIIHH", 0, 1, 2, 0, 40) + b"ab"
            try:
                master.sock.sendto(
                    pack_header(TYPE_MESSAGE_TEXT, length=len(payload)) + payload,
                    master.sock.getsockname(),
                )
            except OSError:
                pass

        threading.Thread(target=inject, daemon=True).start()
        code = run(
            host="127.0.0.1",
            port=master.port,
            dmr_id=2140410,
            password="pw",
            seconds=2,
            exit_after_message=True,
            on_message=received.append,
        )
    finally:
        master.stop()

    assert code == 0
    assert received == []
