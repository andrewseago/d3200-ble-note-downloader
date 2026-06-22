"""Tests for current D3200 BLE/cloud known-plaintext geometry."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.known_plaintext import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_PREFIX_LEN,
    DEFAULT_SUFFIX_LEN,
    OPUS_FRAME_SAMPLES,
    OPUS_PACKET_SIZE,
    build_keystream_target,
    build_ogg_opus,
    build_opus_head,
    build_opus_tags,
    load_pair,
    ogg_crc,
    parse_ogg_opus_packets,
    strip_ble_chunks,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FILE_ID = "4aaa136a"

EXPECTED_RAW_BYTES = 198_112
EXPECTED_BLE_CHUNKS = 1_208
EXPECTED_CLOUD_PACKETS = 985
EXPECTED_EXTRA_BLE_FRAMES = 223

OFFSET_0_KS0 = bytes.fromhex("155896c1d0598bfe707380dfadd9e7be")
OFFSET_0_KS1 = bytes.fromhex("392667a9ab042b854ae4902ed7ce0f40")
LAST_OFFSET_KS0 = bytes.fromhex("ea34d5523710a0e8f215d36362229e05")
LAST_OFFSET_KS1 = bytes.fromhex("24540dec831347b7be26a8cb180361e7")


@pytest.fixture(scope="module")
def pair():
    raw = REPO_ROOT / "downloads" / f"raw_{FILE_ID}.bin"
    ogg = REPO_ROOT / "downloads" / f"cloud_decrypted_{FILE_ID}.ogg"
    if not (raw.exists() and ogg.exists()):
        pytest.skip("recording fixtures not bundled in the public repo (see downloads/README.md)")
    return load_pair(REPO_ROOT, FILE_ID)


def test_pair_files_exist_and_are_current(pair) -> None:
    assert pair.raw_path.name == f"raw_{FILE_ID}.bin"
    assert pair.ogg_path.name == f"cloud_decrypted_{FILE_ID}.ogg"
    assert pair.raw_path.exists()
    assert pair.ogg_path.exists()
    assert len(pair.raw) == EXPECTED_RAW_BYTES


def test_ble_chunk_geometry(pair) -> None:
    assert len(pair.raw) % DEFAULT_CHUNK_SIZE == 0
    assert pair.ble_chunk_count == EXPECTED_BLE_CHUNKS
    assert pair.ble_payloads[0] == pair.raw[DEFAULT_PREFIX_LEN : DEFAULT_CHUNK_SIZE - DEFAULT_SUFFIX_LEN]
    assert len(pair.ble_payloads[0]) == OPUS_PACKET_SIZE


def test_cloud_opus_packet_geometry(pair) -> None:
    assert pair.audio_packet_count == EXPECTED_CLOUD_PACKETS
    assert {len(packet) for packet in pair.opus_packets} == {OPUS_PACKET_SIZE}
    assert sum(len(packet) for packet in pair.opus_packets) == EXPECTED_CLOUD_PACKETS * OPUS_PACKET_SIZE


def test_alignment_window(pair) -> None:
    assert pair.extra_ble_frames == EXPECTED_EXTRA_BLE_FRAMES
    assert len(pair.candidate_offsets) == EXPECTED_EXTRA_BLE_FRAMES + 1
    assert pair.candidate_offsets.start == 0
    assert pair.candidate_offsets.stop == EXPECTED_EXTRA_BLE_FRAMES + 1


def test_current_ble_chunk_prefix_suffix_observations(pair) -> None:
    chunk0 = pair.raw[:DEFAULT_CHUNK_SIZE]
    chunk1 = pair.raw[DEFAULT_CHUNK_SIZE : 2 * DEFAULT_CHUNK_SIZE]
    assert chunk0[:2] == bytes.fromhex("0002")
    assert chunk0[162:164] == bytes.fromhex("6bff")
    assert chunk1[:2] == bytes.fromhex("0000")
    assert chunk1[162:164] == bytes.fromhex("e061")


def test_strip_ble_chunks_drops_partial_tail() -> None:
    raw = (
        b"\x00\x02"
        + b"\xaa" * OPUS_PACKET_SIZE
        + b"\x11\x22"
        + b"\x00\x00"
        + b"\xbb" * OPUS_PACKET_SIZE
        + b"\x33\x44"
        + b"partial"
    )
    payloads = strip_ble_chunks(raw)
    assert payloads == [b"\xaa" * OPUS_PACKET_SIZE, b"\xbb" * OPUS_PACKET_SIZE]


def test_keystream_target_offset_0(pair) -> None:
    target = build_keystream_target(pair, 0)
    assert target.ks0 == OFFSET_0_KS0
    assert target.ks1 == OFFSET_0_KS1


def test_keystream_target_last_candidate_offset(pair) -> None:
    target = build_keystream_target(pair, EXPECTED_EXTRA_BLE_FRAMES)
    assert target.ks0 == LAST_OFFSET_KS0
    assert target.ks1 == LAST_OFFSET_KS1


def test_keystream_target_rejects_out_of_range_offset(pair) -> None:
    with pytest.raises(ValueError, match="outside candidate range"):
        build_keystream_target(pair, EXPECTED_EXTRA_BLE_FRAMES + 1)


def _iter_ogg_pages(data: bytes) -> list[bytes]:
    pages: list[bytes] = []
    pos = 0
    while pos + 27 <= len(data) and data[pos : pos + 4] == b"OggS":
        segment_count = data[pos + 26]
        segment_table = data[pos + 27 : pos + 27 + segment_count]
        page_end = pos + 27 + segment_count + sum(segment_table)
        pages.append(data[pos:page_end])
        pos = page_end
    return pages


def _page_payload(page: bytes) -> bytes:
    segment_count = page[26]
    segment_table = page[27 : 27 + segment_count]
    payload_start = 27 + segment_count
    return page[payload_start : payload_start + sum(segment_table)]


def test_build_ogg_opus_round_trips_cloud_packets(pair) -> None:
    packets = pair.opus_packets[:5]
    generated = build_ogg_opus(packets)
    assert generated[:4] == b"OggS"
    assert parse_ogg_opus_packets(generated) == packets


def test_build_ogg_opus_headers_match_cloud_metadata(pair) -> None:
    generated_pages = _iter_ogg_pages(build_ogg_opus(pair.opus_packets[:1]))
    cloud_pages = _iter_ogg_pages(pair.ogg_path.read_bytes())

    assert _page_payload(generated_pages[0]) == build_opus_head()
    assert _page_payload(generated_pages[1]) == build_opus_tags()
    assert _page_payload(generated_pages[0]) == _page_payload(cloud_pages[0])
    assert _page_payload(generated_pages[1]) == _page_payload(cloud_pages[1])


def test_build_ogg_opus_crc_granule_and_eos(pair) -> None:
    packets = pair.opus_packets[:3]
    pages = _iter_ogg_pages(build_ogg_opus(packets))
    assert len(pages) == 5

    for page in pages:
        stored_crc = int.from_bytes(page[22:26], "little")
        zeroed_page = page[:22] + b"\x00\x00\x00\x00" + page[26:]
        assert ogg_crc(zeroed_page) == stored_crc

    assert pages[0][5] == 0x02
    assert pages[2][5] == 0x00
    assert pages[-1][5] == 0x04
    assert int.from_bytes(pages[2][6:14], "little") == OPUS_FRAME_SAMPLES
    assert int.from_bytes(pages[-1][6:14], "little") == len(packets) * OPUS_FRAME_SAMPLES
