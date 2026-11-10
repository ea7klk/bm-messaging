"""Receive-only ODTP runner: authenticate as one DMR ID and print inbound SMS.

Credentials come from the environment so nothing sensitive lands in Git:

    BM_PASSWORD   the Selfcare "hotspot security password" for that DMR ID

Note: ODTP authenticates with the hotspot password from Selfcare, not the
dashboard account password. Verified against masters 2141 and 2081 on
2026-11-10.

Examples
--------
Prove the master endpoint is reachable and speaks Rewind (no credentials):

    python receive.py --probe --master 84.232.5.113

Listen for private SMS addressed to EA7KLK (DMR ID 2140410):

    BM_PASSWORD=... python receive.py --dmr-id 2140410 --master 84.232.5.113 --seconds 300

Exit as soon as one message is received:

    BM_PASSWORD=... python receive.py --exit-after-message --seconds 300
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from odtp import (
    HEADER_SIZE,
    TYPE_CHALLENGE,
    TYPE_MESSAGE_TEXT,
    OdtpProtocolError,
    OdtpReceiver,
    TextMessage,
    pack_keep_alive,
    parse_header,
    parse_message_text,
)

KEEP_ALIVE_INTERVAL = 5.0
DEFAULT_PORT = 54006
DEFAULT_DMR_ID = 2140410
DEFAULT_MASTER = "84.232.5.113"  # master 2141


@dataclass(frozen=True)
class FrameMeta:
    """Everything observed about one inbound text frame."""

    observed_at: datetime
    connected_at: datetime
    authenticated_at: datetime | None
    master: str
    port: int
    dmr_id: int
    frame_index: int
    type: int
    flags: int
    number: int
    declared_length: int
    payload_length: int
    message: TextMessage
    raw_payload: bytes
    keep_alives_sent: int
    undecodable: int


def format_report(meta: FrameMeta) -> str:
    """Render a receipt block: the message plus the protocol metadata around it."""
    text_bytes = len(meta.message.text.encode("utf-16-le"))
    scope = "group" if meta.message.is_group else "private"
    uptime = (meta.observed_at - meta.connected_at).total_seconds()

    if meta.authenticated_at is None:
        since_auth = "never (n/a)"
    else:
        since_auth = f"{meta.authenticated_at.isoformat(timespec='milliseconds')} " \
                     f"(+{(meta.observed_at - meta.authenticated_at).total_seconds():.3f}s)"

    rows = [
        ("observed_at", meta.observed_at.isoformat(timespec="milliseconds")),
        ("master", f"{meta.master}:{meta.port}"),
        ("terminal_id", str(meta.dmr_id)),
        ("frame_index", str(meta.frame_index)),
        ("frame_type", f"0x{meta.type:04x}"),
        ("flags", f"0x{meta.flags:04x}"),
        ("seq", str(meta.number)),
        ("declared_length", f"{meta.declared_length} (payload {meta.payload_length})"),
        ("source_id", str(meta.message.source_id)),
        ("destination_id", str(meta.message.destination_id)),
        ("option", f"0x{meta.message.option:04x} ({meta.message.option}) {scope}"),
        ("encoding", "UTF-16LE"),
        ("text_bytes", str(text_bytes)),
        ("text_chars", str(len(meta.message.text))),
        ("connected_at", f"{meta.connected_at.isoformat(timespec='milliseconds')} (+{uptime:.1f}s)"),
        ("authenticated", since_auth),
        ("keep_alives_sent", str(meta.keep_alives_sent)),
        ("undecodable_frames", str(meta.undecodable)),
    ]

    width = max(len(name) for name, _ in rows)
    body = "\n".join(f"  {name:<{width}}  {value}" for name, value in rows)
    return (
        "=== message received ===\n"
        f"{body}\n"
        f"  {'text':<{width}}  {meta.message.text!r}\n"
        f"  {'payload_hex':<{width}}  {meta.raw_payload.hex()}\n"
        "======================="
    )


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _log(kind: str, text: str) -> None:
    print(f"{_stamp()} {kind:<8} {text}", flush=True)


def probe(master: str, port: int, dmr_id: int) -> int:
    """Send one keep-alive and report whatever the server says. No auth."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    packet = pack_keep_alive(dmr_id, number=1, description="bm-messaging-spike/probe")
    _log("send", f"keep-alive {len(packet)}B -> {master}:{port} (dmr_id={dmr_id})")
    sock.sendto(packet, (master, port))
    try:
        data, addr = sock.recvfrom(65535)
    except socket.timeout:
        _log("error", "no reply within 10s")
        return 1
    finally:
        sock.close()

    try:
        header = parse_header(data)
    except OdtpProtocolError as exc:
        _log("error", f"unparseable reply from {addr}: {exc}")
        return 1

    if header.type == TYPE_CHALLENGE:
        salt = data[HEADER_SIZE:HEADER_SIZE + header.length]
        _log("recv", f"CHALLENGE from {addr[0]}:{addr[1]} salt={salt.hex()} len={header.length}")
        _log("ok", "master speaks Rewind; supply BM_PASSWORD to authenticate")
        return 0

    _log("recv", f"type=0x{header.type:04x} len={header.length} from {addr[0]}:{addr[1]}")
    return 0


def run(
    host: str = DEFAULT_MASTER,
    port: int = DEFAULT_PORT,
    dmr_id: int = DEFAULT_DMR_ID,
    password: str = "",
    seconds: float = 120.0,
    exit_after_message: bool = False,
    on_message: Callable[[TextMessage], None] | None = None,
    report: bool = False,
    sink: Callable[[str], None] | None = None,
    verbose: bool = True,
) -> int:
    """Hold one terminal connection. Returns 0 on success, 2 if never authenticated."""

    log = _log if verbose else (lambda *_: None)
    emit = sink if sink is not None else print
    got_message = False
    connected_at = datetime.now(timezone.utc)
    authenticated_at: datetime | None = None
    frame_index = 0
    keep_alives_sent = 0

    def default_on_message(message: TextMessage) -> None:
        scope = "group" if message.is_group else "private"
        log("message", f"{scope} from {message.source_id} -> {message.destination_id}: {message.text!r}")

    def handle_message(message: TextMessage) -> None:
        nonlocal got_message
        got_message = True
        (on_message or default_on_message)(message)

    def on_status(status):
        verdict = "delivered" if status.succeeded else f"failed(0x{status.status:02x})"
        log("status", f"{status.source_id} -> {status.destination_id}: {verdict}")

    def on_report(text):
        log("report", text)

    def on_close():
        log("closed", "server sent REWIND_TYPE_CLOSE")

    receiver = OdtpReceiver(
        dmr_id=dmr_id,
        password=password,
        on_message=handle_message,
        on_status=on_status,
        on_report=on_report,
        on_close=on_close,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((host, port))
    sock.settimeout(1.0)

    log("connect", f"udp {host}:{port} as dmr_id={dmr_id}")
    sock.send(receiver.keep_alive_packet())
    keep_alives_sent += 1

    deadline = time.monotonic() + seconds
    next_keep_alive = time.monotonic() + KEEP_ALIVE_INTERVAL
    authed_logged = False
    errors_seen = 0

    try:
        while time.monotonic() < deadline:
            if receiver.authenticated and not authed_logged:
                authenticated_at = datetime.now(timezone.utc)
                log("auth", "authenticated")
                authed_logged = True

            try:
                data = sock.recv(65535)
            except socket.timeout:
                data = None

            if data:
                frame_index += 1
                pending: FrameMeta | None = None
                try:
                    header = parse_header(data)
                except OdtpProtocolError:
                    log("recv", f"unparseable {len(data)}B")
                    header = None

                if header is not None:
                    payload = data[HEADER_SIZE:HEADER_SIZE + header.length]
                    if header.type == TYPE_MESSAGE_TEXT:
                        # Show payload for text frames so odd ones are diagnosable.
                        log("recv", f"type=0x0a10 len={header.length} payload={payload.hex()}")
                        try:
                            parsed = parse_message_text(payload)
                        except OdtpProtocolError:
                            parsed = None
                        if parsed is not None:
                            pending = FrameMeta(
                                observed_at=datetime.now(timezone.utc),
                                connected_at=connected_at,
                                authenticated_at=authenticated_at,
                                master=host,
                                port=port,
                                dmr_id=dmr_id,
                                frame_index=frame_index,
                                type=header.type,
                                flags=header.flags,
                                number=header.number,
                                declared_length=header.length,
                                payload_length=len(payload),
                                message=parsed,
                                raw_payload=payload,
                                keep_alives_sent=keep_alives_sent,
                                undecodable=receiver.errors,
                            )
                    else:
                        log("recv", f"type=0x{header.type:04x} len={header.length}")

                for outbound in receiver.handle(data):
                    sock.send(outbound)

                if receiver.errors > errors_seen:
                    errors_seen = receiver.errors
                    log("error", f"undecodable frame ({errors_seen} total)")

                if pending is not None and report:
                    emit(format_report(pending))

                if got_message and exit_after_message:
                    log("exit", "message received; stopping")
                    return 0

            now = time.monotonic()
            if now >= next_keep_alive:
                sock.send(receiver.keep_alive_packet())
                keep_alives_sent += 1
                next_keep_alive = now + KEEP_ALIVE_INTERVAL
    except KeyboardInterrupt:
        return 0
    finally:
        sock.close()

    if not receiver.authenticated:
        log("warn", f"never authenticated ({receiver.errors} protocol errors)")
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dmr-id", type=int, default=DEFAULT_DMR_ID, help="7-digit DMR ID, no hotspot suffix")
    parser.add_argument("--master", default=DEFAULT_MASTER, help="master IP (master 2141 by default)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="ODTP UDP port")
    parser.add_argument("--seconds", type=float, default=120.0, help="how long to listen")
    parser.add_argument("--exit-after-message", action="store_true",
                        help="stop and exit 0 as soon as one message is received")
    parser.add_argument("--report", action="store_true",
                        help="print the message with its protocol metadata before exiting")
    parser.add_argument("--probe", action="store_true", help="send a keep-alive and report the reply, no auth")
    args = parser.parse_args(argv)

    if args.probe:
        return probe(args.master, args.port, args.dmr_id)

    password = os.environ.get("BM_PASSWORD")
    if not password:
        _log("error", "BM_PASSWORD is not set; use --probe to test reachability without credentials")
        return 1

    return run(
        host=args.master,
        port=args.port,
        dmr_id=args.dmr_id,
        password=password,
        seconds=args.seconds,
        exit_after_message=args.exit_after_message,
        report=args.report,
    )


if __name__ == "__main__":
    sys.exit(main())
