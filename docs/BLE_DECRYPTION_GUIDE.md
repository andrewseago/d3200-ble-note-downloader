# Soundcore D3200 BLE Audio Decryption — Technical Reference

## Overview

The Anker Soundcore D3200 ("soundcore Work") voice recorder encrypts audio files stored on-device using AES-256-CTR with per-file keys. These keys are wrapped in the BLE detail response using a session-derived key. This document describes the complete key derivation and decryption process for BLE-downloaded audio.

The protocol uses standard cryptographic primitives (ECDH P-256, HKDF-SHA256, AES-256-CTR) with hardcoded parameters. No device-specific secrets or cloud accounts are required.

---

## Protocol Summary

```
BLE Client                              D3200 Device
    |                                        |
    |--- Auth token (0327) ---------------->|
    |--- Timestamp sync (14a6) ------------>|
    |                                        |
    |--- File list query (0e0c) ----------->|
    |<-- File list response ----------------|   File IDs + sizes
    |                                        |
    |--- ECDH pubkey (014b) --------------->|
    |<-- Device pubkey + nonce (016b) ------|   Session ECDH established
    |    [session_key = HKDF(shared_secret)] |
    |                                        |
    |--- File detail request (0712) -------->|
    |<-- Detail response (0761) -------------|   Contains wrapped fileKey
    |<-- Audio chunks (08b0) x N ------------|   AES-CTR encrypted Opus
    |<-- Transfer complete (0a13) -----------|
    |                                        |
```

The detail request (`0712`) is what starts the audio transfer — the device
streams the `08b0` audio chunks immediately after the `0761` detail response,
without a separate download-trigger command.

> **Note on the handshake:** the device performs a **single** ECDH exchange
> (one `014b`). Earlier analysis hypothesized a two-stage "transport then QC"
> handshake; capture analysis of the real app showed that is not what happens.
> One `014b` with the session keypair establishes the key material used for all
> file decryption. The terms "QC key" and "session key" are used interchangeably
> here and in the code.

---

## Stage 1: Pre-handshake setup (auth, time, file list)

Before the key exchange, the client sends an auth token and a timestamp, then
queries the file list. These match the real app's command order.

- **Auth token (opcode `0327`):** a fixed Base64 token is sent. The device does
  not validate it; it is the same constant across units and is **not** a secret.
- **Timestamp sync (opcode `14a6`):** the current Unix time, little-endian.
- **File list query (opcode `0e0c`), paginated:** the response contains, for
  each recording, a 4-byte little-endian file ID followed by a 4-byte
  little-endian size. (See [File ID Format](#file-id-format).)

---

## Stage 2: ECDH Handshake (single 014b)

The client performs one ECDH key exchange using NIST P-256 (secp256r1) with its
session ("QC") keypair. The resulting shared secret feeds the HKDF in Stage 3.

### Client sends (opcode 014b):
- 1 byte: `0x00` (flags)
- 1 byte: `0x04` (uncompressed EC point indicator)
- 64 bytes: client public key (X || Y, big-endian)

### Device responds (opcode 016b):
- 1 byte: `0x00` (status)
- 1 byte: `0x04` (uncompressed)
- 64 bytes: device public key (X || Y, big-endian)
- trailing bytes: a device nonce (the response also echoes material equal to the
  ECDH shared secret, observed during instrumentation, but the client computes
  the shared secret itself and does not rely on this).

### Shared secret computation:
```
shared_secret = ECDH(client_private, device_public).x
```

This 32-byte shared secret is the input to the session-key HKDF below.

---

## Stage 3: Session-Key Derivation (HKDF)

The session key (a.k.a. QC_KEY) is derived from the ECDH shared secret using
HKDF-SHA256 with hardcoded parameters.

### Parameters:
| Parameter | Value |
|-----------|-------|
| Algorithm | HKDF-SHA256 (RFC 5869) |
| Salt | `0x010203` (3 bytes) |
| IKM | `shared_secret` (32 bytes from Stage 2) |
| Info | `0x010203` (3 bytes) |
| Output length | 32 bytes |

### Computation:
```
PRK = HMAC-SHA256(key=0x010203, msg=qc_shared_secret)
QC_KEY = HMAC-SHA256(key=PRK, msg=0x010203 || 0x01)
```

The trailing `0x01` is the HKDF-Expand counter for the first (and only) output block.

### Verification:
Known test vector:
```
qc_shared_secret = 88B5306A1642A4D01609F9B16AF61E398BC7F8693B709435C4121F4F33E528BA
QC_KEY           = 97382A6286020CF661AD032FE15A1B40D0EB71121E455EE4030423EC0B93D722
```

---

## Stage 4: File Detail Response and Key Unwrap

After requesting file metadata (opcode 0712) for a given file ID, the device
returns a 97-byte detail response (opcode 0761) and then immediately begins
streaming the encrypted audio chunks for that file.

### Detail response structure (97 bytes):
| Offset | Length | Field |
|--------|--------|-------|
| 0-8 | 9 | RCSP frame header |
| 9-12 | 4 | File ID (little-endian Unix timestamp) |
| 13-16 | 4 | Reported transfer size (little-endian, bytes) |
| 17-32 | 16 | Audio nonce |
| 33-78 | 46 | Encrypted file-key envelope |
| 79-94 | 16 | Session nonce for key unwrap |
| 95 | 1 | Status |
| 96 | 1 | Trailer/checksum |

### FileKey unwrap:
The 46-byte encrypted envelope at offset 33 contains the per-file AES key. Decrypt it with the HKDF-derived session key and the 16-byte `sessionNonce` using AES-256-CTR.

```
session_key = HKDF-SHA256(shared_secret, salt=010203, info=010203, length=32)
plaintext = AES-256-CTR-decrypt(
    key=session_key,
    IV=detail[79:95],
    ciphertext=detail[33:79],
)
assert plaintext.startswith(b"soundcored3200")
fileKey = plaintext[14:46]
```

This path is validated end-to-end against real device captures: the file key
unwraps to the `soundcored3200`-prefixed envelope, and the decrypted audio
matches a known-good reference of the same recording.

---

## Stage 5: Audio Decryption

### BLE audio chunk format:
Audio data arrives in 164-byte BLE chunks via opcode 08b0.

Each chunk:
| Offset | Length | Content |
|--------|--------|---------|
| 0-1 | 2 | Chunk prefix (usually `0x0000`; `0x0001` for segment markers; `0x0004` for final) |
| 2-161 | 160 | Encrypted audio payload |
| 162-163 | 2 | Chunk trailer |

### Stripping and decrypting:
```
payload = chunk[2:162]
IV = audio_nonce[0:12] || BE32(sequence_number * 10)
opus_packet = AES-256-CTR-decrypt(key=fileKey, IV=IV, ciphertext=payload)
```

Do not use a single continuous CTR stream over the concatenated payloads. The SDK model decrypts each 160-byte packet independently, with `sequence_number * 10` as the 32-bit big-endian counter suffix.

### Validation:
A captured recording decrypts packet-for-packet to match a known-good reference
of the same audio after alignment. The decrypted packets are fixed 160-byte Opus
frames, and `ffprobe` recognizes the generated Ogg as Opus stereo with the
expected duration.

---

## Stage 6: Opus to Playable Audio

The downloader now writes both forms:

- `decrypted_<file_id>.raw_opus` — concatenated 160-byte Opus packets;
- `decrypted_<file_id>.ogg` — playable Ogg/Opus with D3200-compatible metadata.

The local Ogg wrapper uses stereo, preskip `312`, input sample rate `16000`, and 960-sample granule increments.

---

## Complete Decryption in Python

```python
from pathlib import Path

from tools.d3200_sdk_crypto import (
    decrypt_raw_audio,
    derive_session_key,
    parse_file_header,
    unwrap_file_key,
)
from tools.known_plaintext import build_ogg_opus


def decrypt_recording(shared_secret: bytes, detail_path: Path, raw_path: Path, ogg_path: Path) -> bytes:
    detail = detail_path.read_bytes()
    raw = raw_path.read_bytes()

    header = parse_file_header(detail)
    session_key = derive_session_key(shared_secret)
    file_key = unwrap_file_key(session_key, header)
    packets = decrypt_raw_audio(raw, header, file_key)

    opus = b"".join(packets)
    ogg_path.write_bytes(build_ogg_opus(packets))
    return opus
```

---

## BLE Protocol Details

### GATT Services and Characteristics:
| UUID | Direction | Purpose |
|------|-----------|---------|
| 00007777-... | Write | Command channel |
| 00008888-... | Notify | Response channel |

### RCSP Frame Format:
All commands use JieLi RCSP framing:
- `08ee` prefix for commands (client to device)
- `09ff` prefix for responses (device to client)
- 1-byte XOR checksum as final byte

### Key Opcodes:
| Opcode | Name | Description |
|--------|------|-------------|
| 014b | ECC_KEY_EXCHANGE | Send ECDH public key |
| 016b | ECC_KEY_EXCHANGE_RSP | Device ECDH response |
| 0e0c | FILE_LIST_QUERY | List recordings on device |
| 0e64 | FILE_LIST_RSP | File list (IDs + sizes) |
| 0327 | AUTH_TOKEN | Send fixed (non-secret) auth token |
| 14a6 | TIME_SYNC | Sync device clock |
| 0712 | FILE_METADATA_REQ | Request file detail (also starts the audio transfer) |
| 0761 | FILE_DETAIL_RSP | Detail with wrapped key |
| 08b0 | AUDIO_CHUNK | 164-byte encrypted audio |
| 0a13 | TRANSFER_COMPLETE | End of audio stream |

### File ID Format:
File IDs are 4-byte little-endian Unix timestamps (seconds since epoch) marking
when the recording was made. For example, a little-endian file ID of
`00000000` would decode to `0x00000000` = epoch 0; decode with
`int.from_bytes(file_id, "little")` and convert to a date as needed.

---

## Security Notes

- The HKDF salt and info values (`010203`) are hardcoded in the device firmware and iOS/Android app binary. They are identical across all D3200 units.
- No pairing PIN, cloud authentication, or device-specific secret is required to download and decrypt recordings. Any BLE client that completes the ECDH handshakes can access all stored audio.
- The per-file key is generated by the device at recording time and stored alongside the audio. It does not change between download sessions — only the wrapping (via session-specific QC_KEY) changes.
- Cloud-uploaded audio uses a completely separate encryption key (`audio_key` from the Anker cloud API). BLE and cloud keys are independent.

---

## Reference Implementation

See `soundcore_d3200_downloader.py` in this repository for a complete BLE client that implements scanning, pairing, downloading, and decryption.

```bash
# Scan for device
python3 soundcore_d3200_downloader.py --scan-only

# Download and decrypt most recent recording
python3 soundcore_d3200_downloader.py --output ./recordings
```

---

## Acknowledgments

Reverse engineered through BLE protocol analysis, mobile-app binary inspection,
runtime instrumentation, Bluetooth HCI log capture, and differential
cryptanalysis of file-detail responses across multiple capture sessions.
