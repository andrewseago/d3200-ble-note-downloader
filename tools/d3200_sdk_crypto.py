#!/usr/bin/env python3
"""SDK-matched D3200 BLE file decryption helpers."""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FILE_KEY_HEAD = b"soundcored3200"
HKDF_SALT = b"\x01\x02\x03"
HKDF_INFO = b"\x01\x02\x03"

HEADER_MIN_LEN = 97
RAW_FRAME_SIZE = 164
RAW_FRAME_PREFIX_LEN = 2
RAW_FRAME_PAYLOAD_LEN = 160
TRANSFER_UNIT_SIZE = 166
BLOCKS_PER_PACKET = 10


@dataclass(frozen=True)
class D3200FileHeader:
    """Parsed 0x1a/0x07 file-head response."""

    file_id_bytes: bytes
    file_id: int
    file_size: int
    nonce: bytes
    encrypted_file_key: bytes
    session_nonce: bytes
    status: int
    checksum: int | None = None

    @property
    def file_id_hex(self) -> str:
        return self.file_id_bytes.hex()


def aes_ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt/decrypt AES-CTR data."""
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"AES-CTR IV must be 16 bytes, got {len(iv)}")
    cryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return cryptor.update(data) + cryptor.finalize()


def derive_session_key(shared_secret: bytes) -> bytes:
    """Derive the D3200 session key using the SDK HKDF parameters."""
    return hkdf_sha256(shared_secret, HKDF_SALT, HKDF_INFO, 32)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def parse_file_header(data: bytes) -> D3200FileHeader:
    """Parse SDK file-head layout from a full BLE/WiFi header packet."""
    if len(data) < HEADER_MIN_LEN:
        raise ValueError(f"file header must be at least {HEADER_MIN_LEN} bytes, got {len(data)}")
    return D3200FileHeader(
        file_id_bytes=data[9:13],
        file_id=int.from_bytes(data[9:13], "little"),
        file_size=int.from_bytes(data[13:17], "little"),
        nonce=data[17:33],
        encrypted_file_key=data[33:79],
        session_nonce=data[79:95],
        status=data[95],
        checksum=data[96] if len(data) > 96 else None,
    )


def unwrap_file_key(session_key: bytes, header: D3200FileHeader) -> bytes:
    """Decrypt the SDK file-key envelope and return the 32-byte per-file key."""
    plaintext = aes_ctr_crypt(session_key, header.session_nonce, header.encrypted_file_key)
    if len(plaintext) < len(FILE_KEY_HEAD) + 32:
        raise ValueError(f"decrypted file-key envelope too short: {len(plaintext)}")
    if not plaintext.startswith(FILE_KEY_HEAD):
        raise ValueError("decrypted file-key envelope missing soundcored3200 prefix")
    file_key = plaintext[len(FILE_KEY_HEAD) : len(FILE_KEY_HEAD) + 32]
    if len(file_key) != 32:
        raise ValueError(f"file key must be 32 bytes, got {len(file_key)}")
    return file_key


def build_chunk_counter(nonce: bytes, sequence_number: int) -> bytes:
    """Build SDK AES-CTR counter: nonce[0:12] || BE32(sequence * 10)."""
    if sequence_number < 0:
        raise ValueError("sequence_number must be non-negative")
    return nonce[:12].ljust(12, b"\x00") + struct.pack(">I", sequence_number * BLOCKS_PER_PACKET)


def decrypt_data_chunk(file_key: bytes, nonce: bytes, sequence_number: int, data_chunk: bytes) -> bytes:
    """Decrypt one 160-byte D3200 audio data chunk."""
    return aes_ctr_crypt(file_key, build_chunk_counter(nonce, sequence_number), data_chunk)


def iter_raw_frame_payloads(raw_audio: bytes) -> list[tuple[int, bytes]]:
    """Return ``(sequence_number, 160B payload)`` pairs from saved raw BLE data."""
    payloads: list[tuple[int, bytes]] = []
    for sequence_number, offset in enumerate(range(0, len(raw_audio), RAW_FRAME_SIZE)):
        frame = raw_audio[offset : offset + RAW_FRAME_SIZE]
        if len(frame) != RAW_FRAME_SIZE:
            break
        payload = frame[RAW_FRAME_PREFIX_LEN : RAW_FRAME_PREFIX_LEN + RAW_FRAME_PAYLOAD_LEN]
        payloads.append((sequence_number, payload))
    return payloads


def decrypt_raw_audio(raw_audio: bytes, header: D3200FileHeader, file_key: bytes) -> list[bytes]:
    """Decrypt saved raw BLE frames into a list of 160-byte Opus packets."""
    return [
        decrypt_data_chunk(file_key, header.nonce, sequence_number, payload)
        for sequence_number, payload in iter_raw_frame_payloads(raw_audio)
    ]


def load_session_key_from_json(path: Path) -> bytes:
    """Load a session key or derive one from a saved session JSON file."""
    data: dict[str, Any] = json.loads(path.read_text())
    if data.get("qc_key"):
        return bytes.fromhex(data["qc_key"])
    shared_secret = data.get("qc_shared_secret") or data.get("shared_secret")
    if not shared_secret:
        raise ValueError(f"{path} does not contain qc_key or shared_secret")
    return derive_session_key(bytes.fromhex(shared_secret))
