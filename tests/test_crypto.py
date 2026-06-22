"""Tests for D3200 cryptographic operations using known test vectors."""
import hashlib
import hmac as hmac_mod
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from tools.d3200_sdk_crypto import (
    FILE_KEY_HEAD,
    RAW_FRAME_PAYLOAD_LEN,
    aes_ctr_crypt,
    build_chunk_counter,
    decrypt_data_chunk,
    decrypt_raw_audio,
    iter_raw_frame_payloads,
    load_session_key_from_json,
    parse_file_header,
    unwrap_file_key,
)
from tools.known_plaintext import parse_ogg_opus_packets

# === Known-answer test vectors (HKDF session-key derivation) ===

TEST_ECDH_SHARED = bytes.fromhex(
    "88B5306A1642A4D01609F9B16AF61E398BC7F8693B709435C4121F4F33E528BA"
)
TEST_QC_KEY = bytes.fromhex(
    "97382A6286020CF661AD032FE15A1B40D0EB71121E455EE4030423EC0B93D722"
)
HKDF_SALT = bytes.fromhex("010203")
HKDF_INFO = bytes.fromhex("010203")


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


def derive_qc_key(ecdh_shared_secret: bytes) -> bytes:
    prk = hkdf_extract_raw(HKDF_SALT, ecdh_shared_secret)
    return hkdf_expand_raw(prk, HKDF_INFO, 32)


class TestHKDF:
    def test_derive_qc_key_known_vector(self):
        result = derive_qc_key(TEST_ECDH_SHARED)
        assert result == TEST_QC_KEY

    def test_derive_qc_key_output_length(self):
        result = derive_qc_key(TEST_ECDH_SHARED)
        assert len(result) == 32

    def test_hkdf_extract_produces_32_bytes(self):
        prk = hkdf_extract_raw(HKDF_SALT, TEST_ECDH_SHARED)
        assert len(prk) == 32

    def test_hkdf_expand_produces_requested_length(self):
        prk = hkdf_extract_raw(HKDF_SALT, TEST_ECDH_SHARED)
        for length in [16, 32, 48, 64]:
            result = hkdf_expand_raw(prk, HKDF_INFO, length)
            assert len(result) == length

    def test_hkdf_extract_is_hmac_sha256(self):
        expected = hmac_mod.new(HKDF_SALT, TEST_ECDH_SHARED, hashlib.sha256).digest()
        result = hkdf_extract_raw(HKDF_SALT, TEST_ECDH_SHARED)
        assert result == expected

    def test_hkdf_expand_single_block(self):
        prk = hkdf_extract_raw(HKDF_SALT, TEST_ECDH_SHARED)
        t1 = hmac_mod.new(prk, HKDF_INFO + b"\x01", hashlib.sha256).digest()
        result = hkdf_expand_raw(prk, HKDF_INFO, 32)
        assert result == t1

    def test_different_shared_secrets_produce_different_keys(self):
        key1 = derive_qc_key(TEST_ECDH_SHARED)
        key2 = derive_qc_key(b"\x00" * 32)
        assert key1 != key2

    def test_empty_salt_uses_zero_pad(self):
        prk_empty = hkdf_extract_raw(b"", TEST_ECDH_SHARED)
        prk_zeros = hkdf_extract_raw(None, TEST_ECDH_SHARED)
        prk_explicit = hmac_mod.new(b"\x00" * 32, TEST_ECDH_SHARED, hashlib.sha256).digest()
        assert prk_empty == prk_explicit
        assert prk_zeros == prk_explicit


class TestECDH:
    def test_ecdh_shared_secret_length(self):
        assert len(TEST_ECDH_SHARED) == 32

    def test_keypair_generation(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub = priv.public_key().public_numbers()
        x = pub.x.to_bytes(32, "big")
        y = pub.y.to_bytes(32, "big")
        assert len(x) == 32
        assert len(y) == 32

    def test_ecdh_exchange_deterministic(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        priv1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
        priv2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared1 = priv1.exchange(ec.ECDH(), priv2.public_key())
        shared2 = priv2.exchange(ec.ECDH(), priv1.public_key())
        assert shared1 == shared2
        assert len(shared1) == 32


class TestRCSPFraming:
    CMD_PREFIX = bytes([0x08, 0xEE])
    RESP_PREFIX = bytes([0x09, 0xFF])

    def test_xor_checksum(self):
        def xor_checksum(data: bytes) -> int:
            chk = 0
            for b in data:
                chk ^= b
            return chk & 0xFF

        assert xor_checksum(b"\x00") == 0
        assert xor_checksum(b"\xff") == 0xFF
        assert xor_checksum(b"\x01\x02\x03") == 0x01 ^ 0x02 ^ 0x03
        assert xor_checksum(b"\xaa\xaa") == 0

    def test_cmd_prefix(self):
        assert self.CMD_PREFIX == b"\x08\xee"

    def test_resp_prefix(self):
        assert self.RESP_PREFIX == b"\x09\xff"

    def test_handshake_opcode(self):
        assert bytes([0x01, 0x4B]) == b"\x01\x4b"

    def test_detail_opcode(self):
        assert bytes([0x07, 0x61]) == b"\x07\x61"

    def test_audio_chunk_opcode(self):
        assert bytes([0x08, 0xB0]) == b"\x08\xb0"


class TestCloudDecrypt:
    def test_aes_ctr_decrypt_format(self):
        from cryptography.hazmat.backends import default_backend

        key = bytes.fromhex(
            "E17439D676DAF6E54D5D227E9661F0581A4BFADDBBC88722F7A3CA55BB968854"
        )
        nonce = b"\x00" * 12
        icb = nonce + struct.pack(">I", 2)
        plaintext = b"OggS" + b"\x00" * 28
        enc = Cipher(algorithms.AES(key), modes.CTR(icb), default_backend()).encryptor()
        ct = enc.update(plaintext) + enc.finalize()

        dec = Cipher(algorithms.AES(key), modes.CTR(icb), default_backend()).decryptor()
        result = dec.update(ct) + dec.finalize()
        assert result == plaintext
        assert result[:4] == b"OggS"

    def test_counter_starts_at_2(self):
        icb = b"\x00" * 12 + struct.pack(">I", 2)
        assert icb[-4:] == b"\x00\x00\x00\x02"
        assert len(icb) == 16


REPO_ROOT = Path(__file__).resolve().parent.parent

# The captured-recording regression fixtures (real device audio + its session
# key) are intentionally NOT bundled in the public repo. Tests that need them
# skip automatically; see downloads/README.md to supply your own capture.
_FIXTURES = (
    REPO_ROOT / "downloads/detail_4aaa136a.bin",
    REPO_ROOT / "downloads/raw_4aaa136a.bin",
    REPO_ROOT / "downloads/session_1779673792.json",
    REPO_ROOT / "downloads/cloud_decrypted_4aaa136a.ogg",
)
requires_recording_fixtures = pytest.mark.skipif(
    not all(path.exists() for path in _FIXTURES),
    reason="recording fixtures not bundled in the public repo (see downloads/README.md)",
)


@requires_recording_fixtures
class TestSdkFileHeader:
    def test_parse_real_4aaa_header(self):
        header = parse_file_header((REPO_ROOT / "downloads/detail_4aaa136a.bin").read_bytes())
        assert header.file_id_hex == "4aaa136a"
        assert header.file_id == 1_779_673_674
        assert header.file_size == 200_528
        assert header.nonce.hex() == "ad247b28e142d11f051a6b7300000000"
        assert len(header.encrypted_file_key) == 46
        assert header.session_nonce.hex() == "1c8d46fc88faade1a09fec8000000000"
        assert header.status == 0
        assert header.checksum == 0x3A

    def test_transfer_size_matches_166_byte_units(self):
        header = parse_file_header((REPO_ROOT / "downloads/detail_4aaa136a.bin").read_bytes())
        raw = (REPO_ROOT / "downloads/raw_4aaa136a.bin").read_bytes()
        assert header.file_size == (len(raw) // 164) * 166


class TestSdkFileKeyUnwrap:
    """File-key unwrap. The synthetic round-trip needs no fixtures; the real
    captured-recording checks skip when fixtures are absent."""

    SESSION_JSON = REPO_ROOT / "downloads/session_1779673792.json"
    DETAIL = REPO_ROOT / "downloads/detail_4aaa136a.bin"
    EXPECTED_FILE_KEY = bytes.fromhex(
        "0505b1f06ca9a4426c862ad3843dd66cb756a5234f05aa56473db4135682625c"
    )

    @requires_recording_fixtures
    def test_unwrap_real_4aaa_file_key(self):
        session_key = load_session_key_from_json(self.SESSION_JSON)
        header = parse_file_header(self.DETAIL.read_bytes())
        assert unwrap_file_key(session_key, header) == self.EXPECTED_FILE_KEY

    def test_synthetic_file_key_roundtrip(self):
        session_key = bytes(range(32))
        file_key = bytes(range(32, 64))
        session_nonce = b"\x55" * 16
        plaintext = FILE_KEY_HEAD + file_key
        encrypted_file_key = aes_ctr_crypt(session_key, session_nonce, plaintext)
        header_bytes = (
            b"\x09\xff\x00\x00\x01\x1a\x07\x61\x00"
            + b"\x01\x02\x03\x04"
            + (166).to_bytes(4, "little")
            + b"\x44" * 16
            + encrypted_file_key
            + session_nonce
            + b"\x00\x99"
        )
        header = parse_file_header(header_bytes)
        assert unwrap_file_key(session_key, header) == file_key

    @requires_recording_fixtures
    def test_unwrap_rejects_wrong_session_key(self):
        header = parse_file_header(self.DETAIL.read_bytes())
        with pytest.raises(ValueError, match="soundcored3200"):
            unwrap_file_key(b"\x00" * 32, header)


class TestSdkChunkDecrypt:
    def test_counter_uses_sequence_times_ten(self):
        nonce = bytes.fromhex("ad247b28e142d11f051a6b7300000000")
        assert build_chunk_counter(nonce, 0) == nonce[:12] + b"\x00\x00\x00\x00"
        assert build_chunk_counter(nonce, 1) == nonce[:12] + b"\x00\x00\x00\x0a"
        assert build_chunk_counter(nonce, 223) == nonce[:12] + struct.pack(">I", 2230)

    def test_iter_raw_frame_payloads_uses_160_byte_payloads(self):
        raw = b"\x00\x02" + b"\xaa" * 160 + b"\x11\x22"
        raw += b"\x00\x00" + b"\xbb" * 160 + b"\x33\x44"
        raw += b"partial"
        payloads = iter_raw_frame_payloads(raw)
        assert payloads == [(0, b"\xaa" * 160), (1, b"\xbb" * 160)]
        assert all(len(payload) == RAW_FRAME_PAYLOAD_LEN for _, payload in payloads)

    def test_synthetic_chunk_roundtrip(self):
        file_key = bytes(range(32))
        nonce = b"\x01\x02\x03\x04" * 4
        sequence = 17
        plaintext = bytes(range(160))
        ciphertext = aes_ctr_crypt(file_key, build_chunk_counter(nonce, sequence), plaintext)
        assert decrypt_data_chunk(file_key, nonce, sequence, ciphertext) == plaintext

    @requires_recording_fixtures
    def test_real_4aaa_ble_matches_cloud_packets(self):
        header = parse_file_header((REPO_ROOT / "downloads/detail_4aaa136a.bin").read_bytes())
        session_key = load_session_key_from_json(REPO_ROOT / "downloads/session_1779673792.json")
        file_key = unwrap_file_key(session_key, header)
        raw = (REPO_ROOT / "downloads/raw_4aaa136a.bin").read_bytes()
        cloud = (REPO_ROOT / "downloads/cloud_decrypted_4aaa136a.ogg").read_bytes()
        decrypted_packets = decrypt_raw_audio(raw, header, file_key)
        cloud_packets = parse_ogg_opus_packets(cloud)

        assert len(decrypted_packets) == 1_208
        assert len(cloud_packets) == 985
        assert decrypted_packets[223 : 223 + len(cloud_packets)] == cloud_packets
