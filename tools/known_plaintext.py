#!/usr/bin/env python3
"""Known-plaintext helpers for Soundcore D3200 BLE/audio analysis.

The useful oracle is a pair of files for the same recording:

* ``downloads/raw_<file_id>.bin``: BLE-downloaded ciphertext, 164-byte chunks.
* ``downloads/cloud_decrypted_<file_id>.ogg``: cloud-decrypted Ogg/Opus.

The D3200 stores one 160-byte Opus packet per BLE chunk payload. Some BLE
captures contain leading/trailing extra frames relative to the cloud copy, so
alignment is a first-class parameter.
"""
from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CHUNK_SIZE = 164
DEFAULT_PREFIX_LEN = 2
DEFAULT_SUFFIX_LEN = 2
OPUS_PACKET_SIZE = 160
OPUS_CHANNELS = 2
OPUS_FRAME_SAMPLES = 960
OPUS_INPUT_SAMPLE_RATE = 16_000
OPUS_PRE_SKIP = 312
OGG_SERIAL = 0x12345678

OPUS_VENDOR = "SoundCore D3200"
OPUS_COMMENTS = (
    "ENCODER=SoundCore D3200",
    "SAMPLERATE=16000",
    "CHANNELS=2",
    "BITRATE=64000",
)


@dataclass(frozen=True)
class KnownPlaintextPair:
    """Loaded BLE/cloud pair for one file id."""

    file_id: str
    raw_path: Path
    ogg_path: Path
    raw: bytes
    opus_packets: list[bytes]
    chunk_size: int = DEFAULT_CHUNK_SIZE
    prefix_len: int = DEFAULT_PREFIX_LEN
    suffix_len: int = DEFAULT_SUFFIX_LEN

    @property
    def ble_payloads(self) -> list[bytes]:
        return strip_ble_chunks(
            self.raw,
            chunk_size=self.chunk_size,
            prefix_len=self.prefix_len,
            suffix_len=self.suffix_len,
        )

    @property
    def audio_packet_count(self) -> int:
        return len(self.opus_packets)

    @property
    def ble_chunk_count(self) -> int:
        return len(self.ble_payloads)

    @property
    def extra_ble_frames(self) -> int:
        return self.ble_chunk_count - self.audio_packet_count

    @property
    def candidate_offsets(self) -> range:
        if self.extra_ble_frames < 0:
            return range(0)
        return range(self.extra_ble_frames + 1)


@dataclass(frozen=True)
class KeystreamTarget:
    """AES-CTR keystream target derived from one alignment offset."""

    offset: int
    ks0: bytes
    ks1: bytes

    def as_dict(self) -> dict[str, str | int]:
        return {
            "offset": self.offset,
            "ks0": self.ks0.hex(),
            "ks1": self.ks1.hex(),
        }


def parse_ogg_opus_packets(data: bytes) -> list[bytes]:
    """Return Opus packets from an Ogg/Opus file, excluding Opus headers."""
    if data[:4] != b"OggS":
        raise ValueError("missing OggS capture pattern")

    packets: list[bytes] = []
    pos = 0
    while pos + 27 <= len(data):
        if data[pos : pos + 4] != b"OggS":
            break
        segment_count = data[pos + 26]
        segment_table_end = pos + 27 + segment_count
        if segment_table_end > len(data):
            break

        segment_sizes = data[pos + 27 : segment_table_end]
        data_pos = segment_table_end
        packet = bytearray()
        for segment_size in segment_sizes:
            segment_end = data_pos + segment_size
            if segment_end > len(data):
                raise ValueError("truncated Ogg page payload")
            packet.extend(data[data_pos:segment_end])
            data_pos = segment_end
            if segment_size < 255:
                packets.append(bytes(packet))
                packet.clear()
        if packet:
            packets.append(bytes(packet))
        pos = data_pos

    if len(packets) < 3:
        raise ValueError(f"expected OpusHead, OpusTags, and audio packets; got {len(packets)} packets")
    return packets[2:]


def ogg_crc(data: bytes) -> int:
    """Return the Ogg page CRC checksum."""
    crc = 0
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def _packet_lacing(packet: bytes) -> tuple[bytes, bytes]:
    """Return Ogg lacing table and payload for one complete packet."""
    segment_sizes: list[int] = []
    remaining = len(packet)
    while remaining >= 255:
        segment_sizes.append(255)
        remaining -= 255
    segment_sizes.append(remaining)
    if len(segment_sizes) > 255:
        raise ValueError(f"packet too large for one Ogg page: {len(packet)} bytes")
    return bytes(segment_sizes), packet


def _ogg_page(packet: bytes, *, header_type: int, granule: int, serial: int, sequence: int) -> bytes:
    segment_table, payload = _packet_lacing(packet)
    header = (
        b"OggS"
        + bytes([0])
        + bytes([header_type])
        + struct.pack("<Q", granule)
        + struct.pack("<I", serial)
        + struct.pack("<I", sequence)
        + b"\x00\x00\x00\x00"
        + bytes([len(segment_table)])
        + segment_table
    )
    page = header + payload
    checksum = ogg_crc(page)
    return page[:22] + struct.pack("<I", checksum) + page[26:]


def build_opus_head(
    *,
    channels: int = OPUS_CHANNELS,
    pre_skip: int = OPUS_PRE_SKIP,
    input_sample_rate: int = OPUS_INPUT_SAMPLE_RATE,
) -> bytes:
    """Build an OpusHead packet matching D3200 cloud output metadata."""
    return (
        b"OpusHead"
        + bytes([1, channels])
        + struct.pack("<H", pre_skip)
        + struct.pack("<I", input_sample_rate)
        + struct.pack("<h", 0)
        + bytes([0])
    )


def build_opus_tags(vendor: str = OPUS_VENDOR, comments: tuple[str, ...] = OPUS_COMMENTS) -> bytes:
    """Build an OpusTags packet matching D3200 cloud output metadata."""
    vendor_bytes = vendor.encode("utf-8")
    out = bytearray(b"OpusTags")
    out.extend(struct.pack("<I", len(vendor_bytes)))
    out.extend(vendor_bytes)
    out.extend(struct.pack("<I", len(comments)))
    for comment in comments:
        comment_bytes = comment.encode("utf-8")
        out.extend(struct.pack("<I", len(comment_bytes)))
        out.extend(comment_bytes)
    return bytes(out)


def build_ogg_opus(
    packets: list[bytes],
    *,
    serial: int = OGG_SERIAL,
    frame_samples: int = OPUS_FRAME_SAMPLES,
) -> bytes:
    """Wrap 160-byte D3200 raw Opus packets in an Ogg/Opus container."""
    if not packets:
        raise ValueError("cannot build Ogg/Opus with zero audio packets")

    pages = [
        _ogg_page(build_opus_head(), header_type=0x02, granule=0, serial=serial, sequence=0),
        _ogg_page(build_opus_tags(), header_type=0x00, granule=0, serial=serial, sequence=1),
    ]
    for index, packet in enumerate(packets):
        if len(packet) != OPUS_PACKET_SIZE:
            raise ValueError(f"packet {index} is {len(packet)} bytes, expected {OPUS_PACKET_SIZE}")
        header_type = 0x04 if index == len(packets) - 1 else 0x00
        granule = (index + 1) * frame_samples
        pages.append(
            _ogg_page(packet, header_type=header_type, granule=granule, serial=serial, sequence=index + 2)
        )
    return b"".join(pages)


def strip_ble_chunks(
    raw: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    prefix_len: int = DEFAULT_PREFIX_LEN,
    suffix_len: int = DEFAULT_SUFFIX_LEN,
) -> list[bytes]:
    """Return per-chunk BLE payload bytes after stripping fixed framing."""
    payload_len = chunk_size - prefix_len - suffix_len
    if payload_len <= 0:
        raise ValueError("chunk framing leaves no payload bytes")

    payloads: list[bytes] = []
    payload_end = chunk_size - suffix_len
    for offset in range(0, len(raw), chunk_size):
        chunk = raw[offset : offset + chunk_size]
        if len(chunk) != chunk_size:
            break
        payloads.append(chunk[prefix_len:payload_end])
    return payloads


def load_pair(
    repo_root: Path,
    file_id: str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    prefix_len: int = DEFAULT_PREFIX_LEN,
    suffix_len: int = DEFAULT_SUFFIX_LEN,
) -> KnownPlaintextPair:
    """Load one known-plaintext pair from ``downloads/``."""
    file_id = file_id.lower()
    downloads = repo_root / "downloads"
    raw_path = downloads / f"raw_{file_id}.bin"
    ogg_path = downloads / f"cloud_decrypted_{file_id}.ogg"
    if not raw_path.exists():
        raise FileNotFoundError(raw_path)
    if not ogg_path.exists():
        raise FileNotFoundError(ogg_path)

    raw = raw_path.read_bytes()
    if not raw:
        raise ValueError(f"{raw_path} is empty")
    if len(raw) % chunk_size != 0:
        raise ValueError(f"{raw_path} size {len(raw)} is not divisible by chunk size {chunk_size}")

    opus_packets = parse_ogg_opus_packets(ogg_path.read_bytes())
    bad_packet_sizes = sorted({len(packet) for packet in opus_packets if len(packet) != OPUS_PACKET_SIZE})
    if bad_packet_sizes:
        raise ValueError(f"{ogg_path} has non-{OPUS_PACKET_SIZE}B audio packets: {bad_packet_sizes}")

    return KnownPlaintextPair(
        file_id=file_id,
        raw_path=raw_path,
        ogg_path=ogg_path,
        raw=raw,
        opus_packets=opus_packets,
        chunk_size=chunk_size,
        prefix_len=prefix_len,
        suffix_len=suffix_len,
    )


def build_keystream_target(pair: KnownPlaintextPair, offset: int) -> KeystreamTarget:
    """Build the first two AES-CTR keystream blocks for one BLE/cloud alignment."""
    ble = pair.ble_payloads
    if offset not in pair.candidate_offsets:
        raise ValueError(f"offset {offset} outside candidate range 0..{pair.extra_ble_frames}")
    if len(pair.opus_packets[0]) < 32 or len(ble[offset]) < 32:
        raise ValueError("need at least 32 bytes in the first plaintext/ciphertext packet")

    ks0 = bytes(a ^ b for a, b in zip(ble[offset][:16], pair.opus_packets[0][:16]))
    ks1 = bytes(a ^ b for a, b in zip(ble[offset][16:32], pair.opus_packets[0][16:32]))
    return KeystreamTarget(offset=offset, ks0=ks0, ks1=ks1)


def summarize_pair(pair: KnownPlaintextPair) -> dict[str, int | str]:
    """Return machine-readable geometry summary for one pair."""
    return {
        "file_id": pair.file_id,
        "raw_path": str(pair.raw_path),
        "ogg_path": str(pair.ogg_path),
        "raw_bytes": len(pair.raw),
        "ble_chunks": pair.ble_chunk_count,
        "cloud_audio_packets": pair.audio_packet_count,
        "extra_ble_frames": pair.extra_ble_frames,
        "candidate_offsets": len(pair.candidate_offsets),
        "chunk_size": pair.chunk_size,
        "prefix_len": pair.prefix_len,
        "payload_len": pair.chunk_size - pair.prefix_len - pair.suffix_len,
        "suffix_len": pair.suffix_len,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze D3200 BLE/cloud known-plaintext pairs.")
    parser.add_argument("file_id", help="4-byte file id hex, e.g. 4aaa136a")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--offset", type=int, default=0, help="BLE frame alignment offset for keystream target")
    parser.add_argument("--all-targets", action="store_true", help="Emit ks0/ks1 for every candidate offset")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    pair = load_pair(args.repo_root, args.file_id)
    summary = summarize_pair(pair)

    if args.all_targets:
        targets = [build_keystream_target(pair, offset).as_dict() for offset in pair.candidate_offsets]
    else:
        targets = [build_keystream_target(pair, args.offset).as_dict()]

    if args.json:
        print(json.dumps({"summary": summary, "targets": targets}, indent=2))
        return 0

    print(f"file_id: {pair.file_id}")
    print(f"raw:     {pair.raw_path} ({len(pair.raw):,} bytes)")
    print(f"cloud:   {pair.ogg_path} ({pair.audio_packet_count:,} audio packets)")
    print(
        "geometry: "
        f"{pair.ble_chunk_count} BLE chunks, {pair.audio_packet_count} cloud packets, "
        f"{pair.extra_ble_frames} extra BLE frames, {len(pair.candidate_offsets)} candidate offsets"
    )
    for target in targets:
        print(f"offset {target['offset']:>4}: ks0={target['ks0']} ks1={target['ks1']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
