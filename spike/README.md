# ODTP receive spike

> **This is a spike, not production software.** It exists to prove one thing:
> that a plain UDP client can hold a BrandMeister terminal identity for a DMR ID
> and receive SMS without radio hardware. It is a local Python script with no
> packaging, no container image, no deployment manifest, and no test against any
> ID other than `2140410`. Do not build on its interfaces as if they were stable,
> and do not deploy it.

A receive-only spike proving that a plain UDP client can act as a BrandMeister
terminal for a single DMR ID, without any RF hardware, hotspot, or codec.

It implements the authentication handshake and the SMS messages of the
[Open DMR Terminal Protocol](https://wiki.brandmeister.network/index.php/Open_DMR_Terminal_Protocol)
(Rewind, little-endian, 18-byte header, master UDP port `54006`).

Scope: **receive only**. No audio, no transmission, no talkgroup subscription.

## Status: verified end to end

Against master 2141 (`84.232.5.113`), DMR ID `2140410`, on 2026-11-10:

```
15:32:56 connect  udp 84.232.5.113:54006 as dmr_id=2140410
15:32:56 recv     type=0x0002 len=4
15:32:56 recv     type=0x0000 len=0
15:32:56 auth     authenticated
15:33:03 recv     type=0x0a10 len=88 payload=0000...420042005300
15:33:03 message  private from 214999 -> 2140410: 'EA7KLK-0 Third test message from BBS'
15:33:03 exit     message received; stopping
```

Confirmed: the handshake, the salt challenge, the `SHA-256(salt ‖ password)`
digest, the empty-keep-alive success signal, and inbound UTF-16LE text delivery
all work. No subscription was created and none was needed for private messages.

## Credential: the hotspot security password, not the account password

**This contradicts the wiki.** The spec says the digest is computed over "the
user's Brandmeister password" and that it is the password "associated with this
DMR ID". In practice ODTP accepts the **Selfcare "hotspot security password"**.

Evidence, all on 2026-11-10:

- the dashboard account password → challenge received, then silence from masters
  2141, 2081 and 2501 (six attempts, both description encodings)
- the hotspot security password → immediate empty keep-alive from both 2141 and
  2081, i.e. authenticated
- the dashboard account password also fails `/api/login` with a correctly solved
  ALTCHA proof-of-work, so it is not simply a case of a captcha blocking login

Treat the wiki's wording as wrong or stale for this deployment, and expect the
credential requirement to be the hotspot password. Because that password is
per-device and issuable from Selfcare, it is a far better fit for a multi-user
service than an account password would have been: it can be rotated without
touching the account, and it does not unlock the dashboard. The earlier concern
about storing account passwords is therefore much reduced — but the value is
still replayable, so it must be encrypted at rest, not hashed.

## Identity

`EA7KLK` is DMR ID `2140410`. The hotspot registered under that account is
`214041001` (`MMDVM Host`, MMDVM_HS, firmware `20260911_WPSD`), last seen on
master 2141.

ODTP authenticates as the **7-digit subscriber ID**, not the hotspot ID. The
two-digit suffix is rejected, so pass `--dmr-id 2140410`, never `214041001`.

## Credentials handling

Read from the `BM_PASSWORD` environment variable. Never written to disk, logged,
or committed.

## Running

```bash
python3 -m venv .venv && ./.venv/bin/pip install pytest
cd spike

# reachability only, no credentials
../.venv/bin/python receive.py --probe --dmr-id 2140410 --master 84.232.5.113

# listen for 5 minutes
BM_PASSWORD='...' ../.venv/bin/python receive.py \
    --dmr-id 2140410 --master 84.232.5.113 --seconds 300

# stop and exit 0 as soon as one message arrives
BM_PASSWORD='...' ../.venv/bin/python receive.py \
    --dmr-id 2140410 --master 84.232.5.113 --seconds 300 --exit-after-message
```

Pick `--master` from the master where the radio actually lives; a terminal
registered against the wrong master will not see that ID's traffic.

Exit codes: `0` success, `1` missing password, `2` never authenticated.

## Protocol facts established by traffic

- **`option` is not reliably 0 or 128.** The received private message carried
  `option=0x0040`. Classification must key on the `0x80` group bit alone, never
  on an exact match with 0. Locked in by a regression test.
- **Undocumented 16-byte `0x0a10` frame.** Five seconds after authentication the
  master sends a frame typed `MESSAGE_TEXT` whose payload does not fit
  `RewindTextMessageData`:

  ```
  00000000 01000000 58020000 9049a537
  ```

  Read as that struct it claims a 14245-byte body while carrying zero bytes. It
  is byte-identical across sessions, appears before any real traffic, and is not
  a delivery. The spike logs it with its full payload and counts it as an
  undecodable frame rather than crashing. Its meaning is **unknown**; do not
  assume it is harmless for other IDs, but it is not an SMS.
- **Delivery status frames (`0x0a11`) were not observed.** None were sent for
  messages addressed to this ID, which matches the spec's note that status is
  only used for private messages in the sending direction.

## Tests

```bash
cd spike && ../.venv/bin/python -m pytest -q
```

43 tests, no network required.

`test_odtp.py` covers header encoding, the keep-alive payload, the digest,
UTF-16LE decoding for private and group destinations, the observed `0x40`
option, delivery-status decoding, and the receiver state machine (challenge
answered once, auth confirmed on empty keep-alive, malformed datagrams counted
and ignored).

`test_receive.py` drives `run()` against a local fake master over real UDP
sockets: exit-on-message returns promptly instead of waiting out the window, the
loop keeps listening without the flag, a master that never confirms yields exit
2, and injected malformed frames are reported without crashing.

`test_report.py` covers the receipt metadata block: text presence, identity and
route fields, option rendering for the observed `0x40`, group classification via
the `0x80` bit, header and length fields, payload hex, relative timing, the
unauthenticated case, and non-ASCII text.

## What the spike suggests about a real service

- One process can hold many connections: one UDP socket per DMR ID with a
  5-second keep-alive, not a process or thread per user.
- The protocol surface needed for SMS is small: two message types plus the
  handshake.
- The credential is the per-device hotspot password, which is issuable and
  rotatable per user from Selfcare.
- Still unmeasured: whether a private SMS reaches this terminal while the
  physical radio on the same ID is also online, or which endpoint wins.
