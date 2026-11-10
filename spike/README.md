# ODTP receive spike

A receive-only spike proving that a plain UDP client can act as a BrandMeister
terminal for a single DMR ID, without any RF hardware, hotspot, or codec.

It implements the authentication handshake and the two SMS messages of the
[Open DMR Terminal Protocol](https://wiki.brandmeister.network/index.php/Open_DMR_Terminal_Protocol)
(Rewind, little-endian, 18-byte header, master UDP port `54006`).

Scope: **receive only**. No audio, no transmission, no talkgroup subscription.

## Status

Verified live against master 2141 (`84.232.5.113`) on 2026-11-10:

- keep-alive is accepted and the master answers `REWIND_TYPE_CHALLENGE` with a
  4-byte salt
- a wrong password produces no server response, matching the spec
  ("Unsuccessful authentications receive no response")

Not yet verified, because it requires the account password for the target DMR ID:

- successful authentication (server replies with an empty keep-alive)
- delivery of inbound `REWIND_TYPE_MESSAGE_TEXT`
- whether a private SMS reaches the terminal without any subscription, or
  whether a `REWIND_TYPE_SUBSCRIPTION` is required

## Identity

`EA7KLK` is DMR ID `2140410`. The hotspot registered under that account is
`214041001` (`MMDVM Host`, MMDVMM_HS, firmware `20260911_WPSD`), last seen on
master 2141.

ODTP authenticates as the **7-digit subscriber ID**, not the hotspot ID. The wiki
is explicit that the ID must not carry the two-digit hotspot suffix, so pass
`--dmr-id 2140410`, never `214041001`.

## Credentials

The password is the **BrandMeister account password** for that DMR ID, read from
the `BM_PASSWORD` environment variable. It is never written to disk, logged, or
committed.

This matters for the eventual service design: the auth digest is derived per
challenge from a fresh salt, so the password must be recoverable at connect
time. A one-way hash is useless here. Any multi-user build needs per-user
envelope encryption with the KEK in a Kubernetes Secret, not a password column.

## Running

```bash
python3 -m venv .venv && ./.venv/bin/pip install pytest
cd spike

# reachability only, no credentials
../.venv/bin/python receive.py --probe --dmr-id 2140410 --master 84.232.5.113

# authenticated listen for 5 minutes
BM_PASSWORD='...' ../.venv/bin/python receive.py \
    --dmr-id 2140410 --master 84.232.5.113 --seconds 300
```

Pick `--master` from the master where the radio actually lives; a terminal
registered against the wrong master will not see that ID's traffic.

Exit codes: `0` success, `1` missing password, `2` never authenticated.

## Tests

```bash
cd spike && ../.venv/bin/python -m pytest -q
```

26 tests, no network required. They cover header encoding, the keep-alive
payload, the `SHA-256(salt ‖ password)` digest, UTF-16LE text decoding for both
private and group destinations, delivery-status decoding, and the receiver state
machine (challenge answered once, auth confirmed on empty keep-alive, malformed
datagrams counted and ignored rather than crashing the loop).

## What this proves for the real service

- One process can hold many connections: this is a single UDP socket per DMR ID
  with a 5-second keep-alive, not a process or a thread per user.
- The protocol surface needed for SMS is small: two message types plus the
  handshake.
- The hard requirement is credential custody, not networking.
