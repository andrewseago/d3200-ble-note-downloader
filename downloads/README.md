# `downloads/` — runtime output

This directory holds everything the downloader produces at runtime. **None of it
is committed** (see the repo `.gitignore`), because it contains your private data:

| File | Contents |
|------|----------|
| `qc_keypair.json`, `our_keypair.json` | Your persistent ECDH private keys — **secret** |
| `session_<ts>.json` | Per-session ECDH shared secret + derived session key — **secret** |
| `detail_<file_id>.bin` | Raw BLE file-head response (contains the wrapped per-file key) |
| `raw_<file_id>.bin` | Encrypted BLE audio capture |
| `decrypted_<file_id>.raw_opus` | Decrypted raw Opus packets |
| `decrypted_<file_id>.ogg` | Decrypted, playable Ogg/Opus — **your actual recording** |

## Running the regression tests

The fixture-backed tests in `tests/` reference a captured recording (`4aaa136a`)
and its session key. Those fixtures are **not bundled** — they are real decrypted
audio and a real session key, so publishing them would leak private content. The
tests `skip` automatically when the fixtures are absent.

To run the full suite, drop your own capture here with these exact names:

```
downloads/detail_4aaa136a.bin
downloads/raw_4aaa136a.bin
downloads/session_1779673792.json
downloads/cloud_decrypted_4aaa136a.ogg
```

(or adjust `FILE_ID` / the expected constants in `tests/test_framing.py` and
`tests/test_crypto.py` to match your own recording).
