#!/usr/bin/env python3
"""
Soundcore D3200 BLE Downloader & Decryptor — Production Client

Connects to the Anker Soundcore D3200 (soundcore Work) voice recorder via BLE,
downloads encrypted audio recordings, and decrypts them locally.

Protocol: JieLi RCSP over BLE GATT
Crypto:   ECDH P-256 → HKDF-SHA256 session key → AES-CTR file-key unwrap
          → per-chunk AES-CTR audio decryption

Verified SDK-matched file-head layout:
- file_id=data[9:13], file_size=data[13:17], nonce=data[17:33]
- encryptedFileKey=data[33:79], sessionNonce=data[79:95], status=data[95]
- encryptedFileKey decrypts with AES-CTR(session_key, sessionNonce)
- plaintext envelope is b"soundcored3200" || 32-byte fileKey
- each 160-byte audio chunk decrypts with AES-CTR(fileKey, nonce[:12] || BE32(seq * 10))

Usage:
    python3 soundcore_d3200_downloader.py [--scan-only] [--pair-only] [--output DIR]
"""

import asyncio
import hashlib
import hmac as hmac_mod
import json
import struct
import time
from datetime import datetime
from pathlib import Path

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from tools import d3200_sdk_crypto as sdk_crypto
from tools.known_plaintext import build_ogg_opus

# --- GATT ---
RCSP_SERVICE_UUID = "020cf5da-0000-1000-8000-00805f9b34fb"
WRITE_CHAR_UUID   = "00007777-0000-1000-8000-00805f9b34fb"
NOTIFY_CHAR_UUID  = "00008888-0000-1000-8000-00805f9b34fb"

# --- Protocol ---
CMD_PREFIX  = bytes([0x08, 0xee])
RESP_PREFIX = bytes([0x09, 0xff])

# --- Auth token (static, device doesn't validate) ---
AUTH_TOKEN_B64 = "AZDxUbC0xETNAC9H16acXvtLeQ=="

# --- Paths ---
SCRIPT_DIR = Path(__file__).parent
DOWNLOADS  = SCRIPT_DIR / "downloads"
KEYPAIR_FILE = DOWNLOADS / "our_keypair.json"

CHUNK_SIZE = 164  # bytes per BLE data frame


def xor_checksum(data: bytes) -> int:
    chk = 0
    for b in data:
        chk ^= b
    return chk & 0xFF


# ──────────────────────────────────────────────
# ECDH Key Management
# ──────────────────────────────────────────────

def load_or_generate_keypair():
    """Load persistent keypair or generate a new one."""
    if KEYPAIR_FILE.exists():
        with open(KEYPAIR_FILE) as f:
            kp = json.load(f)
        priv_int = int(kp["private_key"], 16)
        priv_key = ec.derive_private_key(priv_int, ec.SECP256R1(), default_backend())
        pub = priv_key.public_key().public_numbers()
        pub_be = pub.x.to_bytes(32, 'big') + pub.y.to_bytes(32, 'big')
        print(f"[+] Loaded keypair from {KEYPAIR_FILE.name}")
        return priv_key, pub_be

    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = priv_key.public_key().public_numbers()
    priv_hex = format(priv_key.private_numbers().private_value, '064x')
    pub_be = pub.x.to_bytes(32, 'big') + pub.y.to_bytes(32, 'big')

    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    with open(KEYPAIR_FILE, 'w') as f:
        json.dump({
            "private_key": priv_hex,
            "public_key": pub_be.hex(),
        }, f, indent=2)
    print(f"[+] Generated new keypair, saved to {KEYPAIR_FILE.name}")
    return priv_key, pub_be


def parse_device_pubkey(resp: bytes):
    """
    Extract device's ECDH public key and extra key material from handshake response.
    Format: SEC1 uncompressed BE at offset 9 (after RCSP header).
    The 0x04 marker is at offset 9, x at 10-41, y at 42-73.
    Extra bytes after the pubkey (before checksum) may contain KDF input.
    Returns: (pub_key, x_bytes, y_bytes, extra_bytes)
    """
    # Try to find 0x04 marker (uncompressed point)
    for offset in [9, 8, 10, 6, 7]:
        if offset < len(resp) and resp[offset] == 0x04 and offset + 65 <= len(resp):
            x_be = resp[offset+1:offset+33]
            y_be = resp[offset+33:offset+65]
            # Validate point is on curve
            try:
                uncompressed = b'\x04' + x_be + y_be
                pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed)
                # Extract extra bytes after pubkey (exclude last byte = checksum)
                extra = resp[offset+65:-1] if len(resp) > offset + 65 + 1 else b''
                print(f"  Device pubkey found at offset {offset}: x={x_be[:8].hex()}...")
                if extra:
                    print(f"  Extra key material ({len(extra)}B): {extra.hex()}")
                return pub, x_be, y_be, extra
            except Exception:
                continue

    # Fallback: try without 0x04 marker at common offsets
    for offset in [10, 9, 8, 6]:
        if offset + 64 <= len(resp):
            x_be = resp[offset:offset+32]
            y_be = resp[offset+32:offset+64]
            try:
                uncompressed = b'\x04' + x_be + y_be
                pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed)
                extra = resp[offset+64:-1] if len(resp) > offset + 64 + 1 else b''
                print(f"  Device pubkey found at offset {offset} (no 0x04): x={x_be[:8].hex()}...")
                if extra:
                    print(f"  Extra key material ({len(extra)}B): {extra.hex()}")
                return pub, x_be, y_be, extra
            except Exception:
                continue

    return None, None, None, b''


# ──────────────────────────────────────────────
# BLE Audio Decryption
# ──────────────────────────────────────────────
# Architecture verified from SoundcoreSDKDemo Android bytecode:
#   - File head response length >= 97B.
#   - Header offsets: file_id[9:13], file_size[13:17], nonce[17:33],
#     encryptedFileKey[33:79], sessionNonce[79:95], status[95].
#   - encryptedFileKey decrypts under QC/session key with AES-CTR(sessionNonce).
#   - Plaintext is b"soundcored3200" || 32-byte fileKey.
#   - Audio chunks decrypt with AES-CTR(fileKey, nonce[:12] || BE32(seq * 10)).


def unwrap_file_key(session_key: bytes, detail_response: bytes) -> bytes:
    """Unwrap the per-file AES key from a full file-head response."""
    header = sdk_crypto.parse_file_header(detail_response)
    return sdk_crypto.unwrap_file_key(session_key, header)


def decrypt_ble_audio(raw_audio: bytes, file_key: bytes, nonce: bytes) -> bytes:
    """Decrypt saved raw BLE chunks into concatenated raw Opus packets."""
    return b"".join(
        sdk_crypto.decrypt_data_chunk(file_key, nonce, sequence_number, payload)
        for sequence_number, payload in sdk_crypto.iter_raw_frame_payloads(raw_audio)
    )


def hkdf_extract_raw(salt, ikm):
    s = salt if salt and len(salt) > 0 else b"\x00" * 32
    return hmac_mod.new(s, ikm, hashlib.sha256).digest()

def hkdf_expand_raw(prk, info, length=32):
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# --- QC/session-key KDF ---
# The session key is HKDF-SHA256 over the ECDH shared secret with hardcoded
# salt = info = 0x010203 (identical across all D3200 units). Verified against a
# known pairing input/output pair; see tests/test_crypto.py for the vector.
HKDF_SALT = bytes.fromhex("010203")
HKDF_INFO = bytes.fromhex("010203")

def derive_qc_key(ecdh_shared_secret: bytes) -> bytes:
    """Derive QC_KEY/session key from ECDH shared secret.

    HKDF-Extract: PRK = HMAC-SHA256(key=0x010203, msg=shared_secret)
    HKDF-Expand:  QC_KEY = HMAC-SHA256(PRK, 0x010203 || 0x01)[:32]
    """
    prk = hkdf_extract_raw(HKDF_SALT, ecdh_shared_secret)
    qc_key = hkdf_expand_raw(prk, HKDF_INFO, 32)
    return qc_key


# ──────────────────────────────────────────────
# BLE Client
# ──────────────────────────────────────────────

class D3200Client:
    def __init__(self, output_dir=None):
        self.client = None
        self.notifications = asyncio.Queue()
        self.priv_key = None
        self.pub_be = None
        self.device_pub = None
        self.shared_secret = None
        self.handshake_extra = b''
        self.auth_response = None
        self.timesync_response = None
        self.output_dir = Path(output_dir) if output_dir else DOWNLOADS

    def _handler(self, sender, data: bytearray):
        self.notifications.put_nowait(bytes(data))

    async def wait_resp(self, timeout=5.0):
        try:
            return await asyncio.wait_for(self.notifications.get(), timeout)
        except asyncio.TimeoutError:
            return None

    async def send(self, data: bytes):
        await self.client.write_gatt_char(WRITE_CHAR_UUID, data, response=False)

    async def scan(self, timeout=15):
        """Scan for D3200 by RCSP service UUID (handles random BLE addresses)."""
        print("[*] Scanning for soundcore Work (RCSP service)...")
        devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
        for addr, (d, adv) in devices.items():
            uuids = [str(u).lower() for u in (adv.service_uuids if adv else [])]
            rssi = adv.rssi if adv else 0
            name = d.name or "(unnamed)"
            if RCSP_SERVICE_UUID.lower() in uuids or (d.name and "soundcore" in d.name.lower()):
                print(f"[+] Found: {name} ({d.address}) RSSI={rssi}")
                return d
        print("[-] Device not found. Is it powered on and not connected to another device?")
        return None

    async def connect(self, device):
        print(f"[*] Connecting to {device.address}...")
        self.client = BleakClient(device.address)
        await self.client.connect()
        print(f"[+] Connected. MTU={self.client.mtu_size}")
        await self.client.start_notify(NOTIFY_CHAR_UUID, self._handler)

    async def handshake(self):
        """ECDH key exchange — single 014b using QC keypair, matching real app protocol.

        The real Soundcore app sends exactly ONE 014b handshake using the QC keypair.
        It does NOT send a separate transport keypair first (our previous two-exchange
        flow was incorrect per btsnoop analysis).

        After the exchange: derives QC_KEY immediately via derive_qc_key() and stores
        it as self.qc_key.
        """
        # Load or generate the QC keypair (persistent across sessions)
        qc_kp_file = self.output_dir / "qc_keypair.json"
        if qc_kp_file.exists():
            with open(qc_kp_file) as f:
                qc_kp = json.load(f)
            self.qc_priv_key = ec.derive_private_key(
                int(qc_kp["private_key"], 16), ec.SECP256R1(), default_backend()
            )
            print(f"[+] Loaded QC keypair from {qc_kp_file.name}")
        else:
            self.qc_priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            qc_priv_num = self.qc_priv_key.private_numbers().private_value
            qc_pub_nums = self.qc_priv_key.public_key().public_numbers()
            DOWNLOADS.mkdir(parents=True, exist_ok=True)
            with open(qc_kp_file, 'w') as f:
                json.dump({
                    "private_key": format(qc_priv_num, '064x'),
                    "public_key_x": format(qc_pub_nums.x, '064x'),
                    "public_key_y": format(qc_pub_nums.y, '064x'),
                }, f, indent=2)
            print(f"[+] Generated new QC keypair, saved to {qc_kp_file.name}")

        # Also keep priv_key/pub_be attributes set (used by legacy callers)
        self.priv_key = self.qc_priv_key
        qc_pub = self.qc_priv_key.public_key().public_numbers()
        qc_pub_be = qc_pub.x.to_bytes(32, 'big') + qc_pub.y.to_bytes(32, 'big')
        self.pub_be = qc_pub_be

        # Build single 014b: 08ee 0000 002e 014b 0004 [64B QC pubkey BE]
        payload = bytes([0x00, 0x2e, 0x01, 0x4b, 0x00, 0x04]) + qc_pub_be
        cmd = CMD_PREFIX + b'\x00\x00' + payload + bytes([xor_checksum(payload)])

        print(f"[*] Sending single 014b ECDH (QC keypair, {len(qc_pub_be)}B BE)...")
        print(f"    QC pubkey: {qc_pub_be[:4].hex()}...{qc_pub_be[-4:].hex()}")
        await self.send(cmd)

        resp = await self.wait_resp(timeout=10)
        if not resp:
            print("[-] No handshake response")
            return False

        print(f"[+] Handshake response: {len(resp)} bytes")
        print(f"    First 20: {resp[:20].hex()}")

        # Parse device pubkey and extra key material
        self.device_pub, dev_x, dev_y, self.handshake_extra = parse_device_pubkey(resp)
        self.device_pub_bytes = (dev_x + dev_y) if (dev_x and dev_y) else b""
        if not self.device_pub:
            print("[-] Could not extract device public key")
            print(f"    Full response: {resp.hex()}")
            return False

        # Compute ECDH shared secret and derive QC_KEY immediately
        self.qc_shared_secret = self.qc_priv_key.exchange(ec.ECDH(), self.device_pub)
        self.shared_secret = self.qc_shared_secret  # keep legacy attribute in sync
        self.qc_nonce = self.handshake_extra
        self.qc_key = derive_qc_key(self.qc_shared_secret)

        # Secret key material is written only to the (gitignored) session JSON,
        # not echoed to stdout.
        print("[+] ECDH complete; session key derived")

        # Session file path (auth/timesync saved in main())
        self._session_file = self.output_dir / f"session_{int(time.time())}.json"
        return True

    async def auth(self):
        """Send static auth token. Saves response for KDF testing."""
        import base64
        print(f"[*] Sending auth (token={AUTH_TOKEN_B64})...")
        token = base64.b64decode(AUTH_TOKEN_B64)
        payload = bytes([0x00, 0x0b, 0x03, 0x27, 0x00, 0x1c]) + token + bytes([0x15])
        cmd = CMD_PREFIX + b'\x00\x00' + payload + bytes([xor_checksum(payload)])
        await self.send(cmd)
        resp = await self.wait_resp(timeout=5)
        if resp:
            self.auth_response = bytes(resp)  # ensure it's a copy, not bytearray view
            print(f"[+] Auth response: {len(resp)}B  {resp.hex()}")

    async def sync_time(self):
        """Sync timestamp to device. Saves response for KDF testing."""
        ts = int(time.time())
        ts_bytes = struct.pack('<I', ts)
        payload = bytes([0x00, 0x01, 0xa6, 0x14, 0x00]) + ts_bytes
        extra = bytes([0x0a, 0x90, 0xff, 0xe6, 0x6a, 0x08])
        full_payload = payload + extra
        cmd = CMD_PREFIX + b'\x00\x00' + full_payload + bytes([xor_checksum(full_payload)])
        print(f"[*] Sending time sync (ts={ts})...")
        await self.send(cmd)
        resp = await self.wait_resp(timeout=5)  # increased timeout
        if resp:
            self.timesync_response = bytes(resp)  # ensure it's a copy, not bytearray view
            print(f"[+] Time sync response: {len(resp)}B  {resp.hex()}")
        else:
            print("[-] Time sync timeout - no response received")

    async def list_files(self):
        """Query recording list with pagination."""
        file_ids = []
        for page in range(10):
            payload = bytes([0x00, 0x1a, 0x0e, 0x0c, 0x00, page, 0x00, 0x2a])
            cmd = CMD_PREFIX + b'\x00\x00' + payload + bytes([xor_checksum(payload)])
            await self.send(cmd)

            resp = await self.wait_resp(timeout=5)
            if not resp:
                break
            payload_start = 10
            page_count = 0
            i = payload_start
            while i + 8 <= len(resp) - 1:
                fid = resp[i:i+4]
                fsize_bytes = resp[i+4:i+8]
                ts = int.from_bytes(fid, 'little')
                fsize = int.from_bytes(fsize_bytes, 'little')
                if 1735000000 < ts < 1800000000 and fsize > 0 and fsize < 10000000:
                    if fid not in file_ids:
                        dt = datetime.fromtimestamp(ts)
                        file_ids.append(fid)
                        print(f"  File: {fid.hex()} → {dt}  size={fsize} bytes")
                    page_count += 1
                    i += 8
                elif fid == b'\x00\x00\x00\x00':
                    break
                else:
                    i += 1
            if page_count == 0:
                break

        if file_ids:
            print(f"[+] Found {len(file_ids)} file IDs across {page+1} pages")
        else:
            print("[-] No file IDs parsed from response")
        return file_ids

    def _try_detail_decrypt(self, file_id: bytes, detail_response: bytes):
        """Decrypt SDK file-head key material with the current session key."""
        try:
            header = sdk_crypto.parse_file_header(detail_response)
            file_key = sdk_crypto.unwrap_file_key(self.qc_key, header)
        except Exception as e:
            print(f"  [detail] file-key unwrap failed: {e}")
            return

        self.device_file_key = file_key
        self.device_file_key_method = "SDK encryptedFileKey/sessionNonce"
        print(f"  [detail] file-key unwrapped (file_id={header.file_id_hex}, size={header.file_size})")

    async def request_file_detail(self, file_id: bytes) -> bytes | None:
        """Send FILE_DETAIL_REQ (cmd=0x07 sub=0x12) and return the 0x0761 response.

        The device may push one or more 0x0612 metadata frames first; those are
        consumed and logged but not returned.  Returns None on timeout.

        Args:
            file_id: 4-byte little-endian file ID.

        Returns:
            Raw 0x0761 response bytes, or None if no response within timeout.
        """
        payload = bytes([0x00, 0x1a, 0x07, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00]) + file_id
        cmd = CMD_PREFIX + b'\x00\x00' + payload + bytes([xor_checksum(payload)])
        await self.send(cmd)

        # Drain incoming frames until we see 0x0761; skip 0x0612 metadata pushes
        deadline = 10.0
        while True:
            data = await self.wait_resp(timeout=deadline)
            if data is None:
                print(f"[-] request_file_detail: timeout (no 0x0761 for {file_id.hex()})")
                return None
            if len(data) < 8:
                continue
            opcode = data[6:8]
            if opcode == bytes([0x07, 0x61]):
                # This is the detail response we want
                return data
            if opcode == bytes([0x06, 0x12]):
                print(f"    [0x0612 metadata, {len(data)}B — skipping]: {data.hex()}")
                continue
            # Any other opcode (e.g. 0x0761 for a different file, audio chunks)
            # is unexpected but non-fatal; log and keep waiting
            print(f"    [request_file_detail] unexpected opcode {opcode.hex()} ({len(data)}B) — ignoring")

    async def download_file(self, file_id: bytes):
        """Download a recording: get detail response + audio data."""
        ts = int.from_bytes(file_id, 'little')
        dt = datetime.fromtimestamp(ts)
        print(f"\n[*] Downloading file {file_id.hex()} (recorded {dt})")

        # Request file metadata (triggers transfer)
        payload = bytes([0x00, 0x1a, 0x07, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00]) + file_id
        cmd = CMD_PREFIX + b'\x00\x00' + payload + bytes([xor_checksum(payload)])
        await self.send(cmd)

        # Collect all responses
        detail_resp = None
        detail_chunks = []  # verbose: record every notification until transfer starts
        audio_chunks = []
        transfer_complete = False

        while not transfer_complete:
            data = await self.wait_resp(timeout=10)
            if data is None:
                if not audio_chunks:
                    print("[-] Timeout waiting for data")
                break

            # VERBOSE: log every pre-audio chunk (before 0x08b0 audio frames start)
            if not audio_chunks and len(data) < 200:
                opcode = data[6:8].hex() if len(data) >= 8 else "??"
                print(
                    f"    [chunk {len(detail_chunks)}] {len(data)}B op={opcode} "
                    f"head={data[:16].hex()} tail={data[-8:].hex()}"
                )
                detail_chunks.append(bytes(data))

            # Identify response type
            if len(data) >= 8 and data[6:8] == bytes([0x07, 0x61]):
                # Detail response (0x0761)
                detail_resp = data
                print(f"[+] Detail response: {len(data)} bytes")
                # Save detail
                detail_file = self.output_dir / f"detail_{file_id.hex()}.bin"
                detail_file.write_bytes(data)
                if hasattr(self, 'qc_key') and self.qc_key:
                    self._try_detail_decrypt(file_id, data)
            elif len(data) >= 8 and data[6:8] == bytes([0x08, 0xb0]):
                # Audio data chunk
                audio_chunks.append(data[12:])  # Skip RCSP header
                if len(audio_chunks) % 100 == 0:
                    print(f"  [{len(audio_chunks)} chunks...]")
            elif len(data) >= 8 and data[6:8] == bytes([0x0a, 0x13]):
                # Transfer complete
                transfer_complete = True
                total = int.from_bytes(data[10:14], 'little') if len(data) >= 14 else 0
                print(f"[+] Transfer complete: {total} bytes reported")
            elif len(data) >= 8 and data[6:8] == bytes([0x06, 0x12]):
                # Metadata response
                print(f"[+] Metadata: {data.hex()}")
            elif len(data) >= 8 and data[6:8] == bytes([0x18, 0x82]):
                # Transfer init
                print(f"[+] Transfer init: {data.hex()}")
            else:
                # Unknown or continuation
                if len(data) > 20:
                    audio_chunks.append(data)

        # Concatenate audio
        raw_audio = b''.join(audio_chunks)
        print(f"[+] Raw audio: {len(raw_audio)} bytes from {len(audio_chunks)} chunks")

        # VERBOSE: dump pre-audio notifications for protocol trace comparison.
        if detail_chunks:
            chunk_dump = self.output_dir / f"detail_chunks_{file_id.hex()}.bin"
            with open(chunk_dump, "wb") as f:
                for i, c in enumerate(detail_chunks):
                    f.write(f"--- chunk {i} ({len(c)}B) ---\n".encode())
                    f.write(c + b"\n")
            print(f"[+] Wrote {len(detail_chunks)} pre-audio chunks to {chunk_dump.name}")

        # Save raw
        raw_file = self.output_dir / f"raw_{file_id.hex()}.bin"
        raw_file.write_bytes(raw_audio)
        print(f"[+] Saved raw to {raw_file.name}")

        # === SDK-MATCHED DECRYPTION ===
        if detail_resp and hasattr(self, 'qc_key') and self.qc_key and len(raw_audio) > 164:
            try:
                header = sdk_crypto.parse_file_header(detail_resp)
                file_key = sdk_crypto.unwrap_file_key(self.qc_key, header)
                opus_packets = sdk_crypto.decrypt_raw_audio(raw_audio, header, file_key)
                opus_data = b"".join(opus_packets)
            except Exception as e:
                print(f"[-] SDK decrypt failed: {e}")
            else:
                out_file = self.output_dir / f"decrypted_{file_id.hex()}.raw_opus"
                out_file.write_bytes(opus_data)
                ogg_file = self.output_dir / f"decrypted_{file_id.hex()}.ogg"
                ogg_file.write_bytes(build_ogg_opus(opus_packets))
                print(f"[+] Decrypted {len(opus_data):,} bytes ({len(opus_packets)} packets) → {out_file.name}")
                print(f"[+] Ogg/Opus: {ogg_file.name}")
                if opus_data:
                    toc = opus_data[0]
                    print(f"[+] First Opus TOC: 0x{toc:02x} (config={(toc >> 3) & 0x1f} stereo={(toc >> 2) & 1})")
                return raw_audio, detail_resp

        return raw_audio, detail_resp

    async def disconnect(self):
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            print("[+] Disconnected")


async def amain():
    import argparse
    parser = argparse.ArgumentParser(description="Soundcore D3200 BLE Downloader")
    parser.add_argument("--scan-only", action="store_true", help="Only scan, don't connect")
    parser.add_argument("--pair-only", action="store_true", help="Only do ECDH handshake")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output directory")
    parser.add_argument("--file-id", type=str, default=None, help="Specific file ID (hex) to download")
    args = parser.parse_args()

    client = D3200Client(output_dir=args.output)
    client.output_dir.mkdir(parents=True, exist_ok=True)

    # Scan
    device = await client.scan()
    if not device:
        return
    if args.scan_only:
        return

    # Connect
    await client.connect(device)

    try:
        # Step 1: Auth + time sync (before ECDH, matching real app sequence)
        # We init a temporary "bare" state so auth/timesync can proceed
        await client.auth()
        await client.sync_time()

        # Step 2: List files (pre-ECDH)
        file_ids = await client.list_files()

        if args.pair_only:
            # Still do ECDH for --pair-only mode, just skip file download
            if not await client.handshake():
                return
            print("[+] Pairing complete. Disconnecting.")
            return

        # Resolve which file to download
        if args.file_id:
            fid = bytes.fromhex(args.file_id)
        elif file_ids:
            file_ids_sorted = sorted(file_ids, key=lambda f: int.from_bytes(f, 'little'), reverse=True)
            fid = file_ids_sorted[0]
        else:
            print("[-] No files found on device")
            return

        # Step 3: ECC_KEY_EXCHANGE FIRST — single 014b with QC keypair
        # NOTE: btsnoop shows detail-before-ECDH, but on our device the detail
        # request triggers an automatic download that swallows the ECDH response.
        # So we do ECDH before any detail request to avoid the race condition.
        if not await client.handshake():
            return

        # Save session after ECDH
        session_file = client.output_dir / f"session_{int(time.time())}.json"
        with open(session_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "device_pubkey": client.device_pub_bytes.hex() if getattr(client, 'device_pub_bytes', None) else "",
                "shared_secret": client.shared_secret.hex() if client.shared_secret else "",
                "our_pubkey": client.pub_be.hex() if client.pub_be else "",
                "handshake_extra_equals_ecdh": True,
                "handshake_extra": client.handshake_extra.hex() if client.handshake_extra else "",
                "auth_response": client.auth_response.hex() if client.auth_response else "",
                "timesync_response": client.timesync_response.hex() if client.timesync_response else "",
                "qc_shared_secret": client.qc_shared_secret.hex() if getattr(client, 'qc_shared_secret', None) else "",
                "qc_key": client.qc_key.hex() if getattr(client, 'qc_key', None) else "",
                "qc_nonce": client.qc_nonce.hex() if getattr(client, 'qc_nonce', None) else "",
            }, f, indent=2)
        print(f"[+] Session saved to {session_file.name}")

        # Step 4: FILE_DETAIL_REQ — file head contains encryptedFileKey/sessionNonce.
        print(f"\n[*] Post-ECDH detail request for {fid.hex()}")
        post_detail = await client.request_file_detail(fid)
        if post_detail:
            post_path = client.output_dir / f"detail_post_ecdh_{fid.hex()}.bin"
            post_path.write_bytes(post_detail)
            print(f"[+] Post-ECDH detail: {len(post_detail)}B → {post_path.name}")
            try:
                header = sdk_crypto.parse_file_header(post_detail)
                sdk_crypto.unwrap_file_key(client.qc_key, header)
            except Exception as e:
                print(f"[-] file-key unwrap failed: {e}")
            else:
                print(f"[+] file-key unwrapped (file_id={header.file_id_hex}, size={header.file_size})")
        else:
            print("[-] No post-ECDH detail response")
            post_detail = None

        # Step 5: Download audio (triggers DOWNLOAD_TRIGGER + FILE_DATA_CHUNK stream)
        await client.download_file(fid)

    finally:
        await client.disconnect()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
