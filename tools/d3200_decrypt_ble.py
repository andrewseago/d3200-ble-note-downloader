#!/usr/bin/env python3
"""Decrypt a D3200 BLE raw capture using the SDK file-header layout."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.d3200_sdk_crypto import (  # noqa: E402
    decrypt_raw_audio,
    derive_session_key,
    load_session_key_from_json,
    parse_file_header,
    unwrap_file_key,
)
from tools.known_plaintext import build_ogg_opus, parse_ogg_opus_packets  # noqa: E402


def find_packet_alignment(decrypted_packets: list[bytes], expected_packets: list[bytes]) -> int | None:
    """Return first decrypted packet offset matching all expected packets."""
    if len(expected_packets) > len(decrypted_packets):
        return None
    max_offset = len(decrypted_packets) - len(expected_packets)
    for offset in range(max_offset + 1):
        if decrypted_packets[offset : offset + len(expected_packets)] == expected_packets:
            return offset
    return None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Decrypt D3200 BLE raw audio with SDK-matched crypto.")
    parser.add_argument("--detail", type=Path, required=True, help="detail_<file_id>.bin file header")
    parser.add_argument("--raw", type=Path, required=True, help="raw_<file_id>.bin BLE chunk capture")
    parser.add_argument("--session-json", type=Path, help="session JSON containing qc_key or shared_secret")
    parser.add_argument("--session-key", help="32-byte session key hex")
    parser.add_argument("--shared-secret", help="32-byte ECDH shared secret hex; derives session key")
    parser.add_argument("--out", type=Path, help="write concatenated raw Opus packets")
    parser.add_argument("--ogg-out", type=Path, help="write decrypted audio as Ogg/Opus")
    parser.add_argument("--cloud-ogg", type=Path, help="optional cloud-decrypted Ogg/Opus oracle")
    parser.add_argument("--json", action="store_true", help="print machine-readable summary")
    return parser.parse_args()


def _load_session_key(args: argparse.Namespace) -> bytes:
    provided = [bool(args.session_json), bool(args.session_key), bool(args.shared_secret)]
    if sum(provided) != 1:
        raise ValueError("provide exactly one of --session-json, --session-key, or --shared-secret")
    if args.session_json:
        return load_session_key_from_json(args.session_json)
    if args.session_key:
        return bytes.fromhex(args.session_key)
    return derive_session_key(bytes.fromhex(args.shared_secret))


def main() -> int:
    args = _parse_args()
    session_key = _load_session_key(args)
    header = parse_file_header(args.detail.read_bytes())
    file_key = unwrap_file_key(session_key, header)
    packets = decrypt_raw_audio(args.raw.read_bytes(), header, file_key)
    opus = b"".join(packets)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(opus)

    if args.ogg_out:
        args.ogg_out.parent.mkdir(parents=True, exist_ok=True)
        args.ogg_out.write_bytes(build_ogg_opus(packets))

    comparison: dict[str, int | bool | None] = {}
    if args.cloud_ogg:
        cloud_packets = parse_ogg_opus_packets(args.cloud_ogg.read_bytes())
        alignment = find_packet_alignment(packets, cloud_packets)
        comparison = {
            "cloud_packets": len(cloud_packets),
            "alignment": alignment,
            "all_cloud_packets_match": alignment is not None,
        }

    summary = {
        "file_id": header.file_id_hex,
        "file_timestamp": header.file_id,
        "reported_transfer_size": header.file_size,
        "status": header.status,
        "raw_packets": len(packets),
        "raw_opus_bytes": len(opus),
        "session_key": session_key.hex(),
        "file_key": file_key.hex(),
        "output": str(args.out) if args.out else None,
        "ogg_output": str(args.ogg_out) if args.ogg_out else None,
        **comparison,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print(f"file_id: {summary['file_id']} ({summary['file_timestamp']})")
    print(f"reported_transfer_size: {summary['reported_transfer_size']}")
    print(f"raw_packets: {summary['raw_packets']}")
    print(f"raw_opus_bytes: {summary['raw_opus_bytes']}")
    print(f"file_key: {summary['file_key']}")
    if comparison:
        print(f"cloud_packets: {comparison['cloud_packets']}")
        print(f"alignment: {comparison['alignment']}")
        print(f"all_cloud_packets_match: {comparison['all_cloud_packets_match']}")
    if args.out:
        print(f"wrote: {args.out}")
    if args.ogg_out:
        print(f"wrote_ogg: {args.ogg_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
