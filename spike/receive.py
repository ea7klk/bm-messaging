"""Receive-only ODTP runner: authenticate as one DMR ID and print inbound SMS.

Credentials come from the environment so nothing sensitive lands in Git:

    BM_PASSWORD   the BrandMeister account password for that DMR ID

Examples
--------
Prove the master endpoint is reachable and speaks Rewind (no credentials):

    python receive.py --probe --master 84.232.5.113

Listen for private SMS addressed to EA7KLK (DMR ID 2140410):

    BM_PASSWORD=... python receive.py --dmr-id 2140410 --master 84.232.5.113 --seconds 300
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from datetime import datetime, timezone

from odtp import (
    HEADER_SIZE,
    TYPE_CHALLENGE,
    OdtpProtocolError,
    OdtpReceiver,
    pack_keep_alive,
    parse_header,
)

KEEP_ALIVE_INTERVAL = 5.0
DEFAULT_PORT = 54006


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


def run(master: str, port: int, dmr_id: int, password: str, seconds: float) -> int:
    def on_message(message):
        scope = "group" if message.is_group else "private"
        _log(
            "message",
            f"{scope} from {message.source_id} -> {message.destination_id}: {message.text!r}",
        )

    def on_status(status):
        verdict = "delivered" if status.succeeded else f"failed(0x{status.status:02x})"
        _log("status", f"{status.source_id} -> {status.destination_id}: {verdict}")

    def on_report(text):
        _log("report", text)

    def on_close():
        _log("closed", "server sent REWIND_TYPE_CLOSE")

    receiver = OdtpReceiver(
        dmr_id=dmr_id,
        password=password,
        on_message=on_message,
        on_status=on_status,
        on_report=on_report,
        on_close=on_close,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((master, port))
    sock.settimeout(1.0)

    _log("connect", f"udp {master}:{port} as dmr_id={dmr_id}")
    sock.send(receiver.keep_alive_packet())

    deadline = time.monotonic() + seconds
    next_keep_alive = time.monotonic() + KEEP_ALIVE_INTERVAL
    authed_logged = False

    try:
        while time.monotonic() < deadline:
            if receiver.authenticated and not authed_logged:
                _log("auth", "authenticated")
                authed_logged = True

            try:
                data = sock.recv(65535)
            except socket.timeout:
                data = None

            if data:
                try:
                    header = parse_header(data)
                    _log("recv", f"type=0x{header.type:04x} len={header.length}")
                except OdtpProtocolError:
                    _log("recv", f"unparseable {len(data)}B")
                for outbound in receiver.handle(data):
                    sock.send(outbound)

            now = time.monotonic()
            if now >= next_keep_alive:
                sock.send(receiver.keep_alive_packet())
                next_keep_alive = now + KEEP_ALIVE_INTERVAL
    except KeyboardInterrupt:
        return 0
    finally:
        sock.close()

    if not receiver.authenticated:
        _log("warn", f"never authenticated ({receiver.errors} protocol errors)")
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dmr-id", type=int, default=2140410, help="7-digit DMR ID, no hotspot suffix")
    parser.add_argument("--master", default="84.232.5.113", help="master IP (master 2141 by default)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="ODTP UDP port")
    parser.add_argument("--seconds", type=float, default=120.0, help="how long to listen")
    parser.add_argument("--probe", action="store_true", help="send a keep-alive and report the reply, no auth")
    args = parser.parse_args(argv)

    if args.probe:
        return probe(args.master, args.port, args.dmr_id)

    password = os.environ.get("BM_PASSWORD")
    if not password:
        _log("error", "BM_PASSWORD is not set; use --probe to test reachability without credentials")
        return 1

    return run(args.master, args.port, args.dmr_id, password, args.seconds)


if __name__ == "__main__":
    sys.exit(main())
