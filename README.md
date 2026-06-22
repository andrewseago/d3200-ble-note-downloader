# Soundcore D3200 BLE Note Downloader

Download and decrypt the voice recordings stored on an **Anker Soundcore D3200**
("soundcore Work") AI voice recorder — entirely over Bluetooth Low Energy, with
**no cloud account and no internet connection** required.

The D3200 stores its recordings on-device as encrypted Opus audio. This project
documents the BLE transfer protocol and the encryption scheme, and ships a
working reference client that pulls a recording off the device and writes a
plain, playable `.ogg` file.

> **Status:** the BLE download + decrypt path is **solved and content-verified** —
> a recording of a spoken test phrase was downloaded over BLE, decrypted locally,
> and transcribed back to the original words. See [How it works](#how-it-works).

## Why

The D3200 is a nice recorder, but getting audio off it normally means going
through the Soundcore app and Anker's cloud. This project exists so the owner of
a device can get their **own** recordings off their **own** hardware, locally,
and feed them into whatever pipeline they like (e.g. local transcription) without
a cloud round-trip.

## Quick start

### Prerequisites

- **Python 3.12+** and a working Bluetooth adapter.
- The **D3200 powered on and disconnected from the Soundcore app.** The recorder
  accepts only one BLE connection at a time — if the phone app is connected (or
  the app is open in the background and auto-reconnects), the scan or connect
  will fail. Force-quit the app, or toggle the phone's Bluetooth off, first.
- **macOS:** the program running Python (your terminal, or your IDE) needs the
  Bluetooth permission under *System Settings → Privacy & Security → Bluetooth*.
  Without it, scanning silently returns no devices. On first run macOS should
  prompt; if it doesn't, add the app manually.
- **Linux:** BlueZ is required (provided by `bleak`'s backend). Running the scan
  may need appropriate Bluetooth permissions for your user.

```bash
git clone https://github.com/andrewseago/d3200-ble-note-downloader.git
cd d3200-ble-note-downloader

python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # installs bleak + cryptography

# 1. Confirm the device is discoverable
python3 soundcore_d3200_downloader.py --scan-only

# 2. Download + decrypt the most recent recording into ./downloads
python3 soundcore_d3200_downloader.py --output downloads

# Or a specific recording by file id (hex), as listed during a scan:
python3 soundcore_d3200_downloader.py --file-id <file_id> --output downloads
```

Output lands in `downloads/`:

- `decrypted_<file_id>.ogg` — playable Ogg/Opus (open it in any audio player)
- `decrypted_<file_id>.raw_opus` — concatenated raw Opus packets
- `raw_<file_id>.bin`, `detail_<file_id>.bin` — the raw BLE capture, for analysis

### Decrypting a previously saved capture (offline)

If you already have a `raw_*.bin` + `detail_*.bin` pair and the session, you can
decrypt without the device:

```bash
python3 tools/d3200_decrypt_ble.py \
    --detail downloads/detail_<file_id>.bin \
    --raw    downloads/raw_<file_id>.bin \
    --session-json downloads/session_<timestamp>.json \
    --ogg-out downloads/decrypted_<file_id>.ogg
```

## Troubleshooting

- **Scan finds nothing.** The device is likely still connected to the Soundcore
  app — disconnect/force-quit it (or toggle phone Bluetooth off). On macOS, also
  confirm your terminal has the Bluetooth permission (see Prerequisites). The
  device uses a rotating BLE address, so the scanner matches on the RCSP service
  UUID, not a fixed MAC — give it the full scan window.
- **Connects, but no files are listed.** Make sure the recorder actually has
  recordings on it, and that it stays powered on and in range during the run.
- **`file-key unwrap failed`.** This almost always means the ECDH handshake
  didn't complete cleanly. Disconnect, wait a moment, and retry; the generated
  `downloads/qc_keypair.json` is reused across runs and is fine to keep.
- **The `.ogg` won't play.** Any Opus-capable player works (VLC, `ffplay`).
  `ffprobe decrypted_<file_id>.ogg` should report an Opus stereo stream.

## How it works

The full protocol and cryptography are documented in
**[docs/BLE_DECRYPTION_GUIDE.md](docs/BLE_DECRYPTION_GUIDE.md)**. In brief:

1. **Transport** — JieLi RCSP framing over BLE GATT (service `020cf5da-…`, write
   char `00007777-…`, notify char `00008888-…`).
2. **Handshake** — ECDH on NIST P-256. The shared secret feeds HKDF-SHA256
   (salt/info = `0x010203`) to derive a 32-byte **session key**.
3. **Per-file key** — the file-detail response carries a 46-byte wrapped key.
   AES-256-CTR-decrypting it with the session key yields
   `b"soundcored3200" || <32-byte fileKey>`.
4. **Audio** — each 160-byte Opus packet is AES-256-CTR-decrypted with `fileKey`
   and a per-packet counter `audio_nonce[0:12] || BE32(sequence * 10)`.
5. **Container** — decrypted packets are wrapped into a standard Ogg/Opus file.

All primitives are standard (ECDH P-256, HKDF-SHA256, AES-256-CTR). No
device-specific secret, PIN, or cloud account is involved.

## Layout

```
soundcore_d3200_downloader.py   Reference BLE client (scan → handshake → download → decrypt)
tools/d3200_sdk_crypto.py       Key derivation, file-key unwrap, packet decryption
tools/known_plaintext.py        Ogg/Opus parsing and D3200-compatible container writer
tools/d3200_decrypt_ble.py      Offline decrypt CLI for saved captures
docs/BLE_DECRYPTION_GUIDE.md    Full protocol + crypto reference
tests/                          Crypto known-vector and Ogg/Opus container tests
```

## Development

```bash
pip install -e ".[dev]"
make test     # pytest (fixture-backed recording tests skip if absent)
make lint     # ruff
```

The test suite proves the crypto with known vectors and synthetic round-trips,
and validates the Ogg/Opus container builder. The end-to-end regression against a
real captured recording is skipped unless you supply your own capture — see
[`downloads/README.md`](downloads/README.md).

## Scope and legal

This is **personal interoperability and data-portability research**, intended for
use by a person on a D3200 they own, to retrieve their own recordings.

- It operates only on hardware you possess and recordings you made.
- It uses standard, openly documented cryptographic primitives. It does not
  redistribute any Anker firmware, app binaries, or proprietary keys, and it
  contains no DRM-circumvention tooling.
- Bluetooth scanning and connecting to other people's devices, or accessing
  recordings that are not yours, is not a supported or condoned use.

You are responsible for complying with your local laws and with Anker's terms of
service. Provided as-is, with no warranty. Not affiliated with or endorsed by
Anker or Soundcore.

## License

[GPL-3.0-or-later](LICENSE).
