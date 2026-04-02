#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path

BLOOM_SIZE = 512 * 1024 * 1024
RNG_COUNTER = 0x726B2B9D438B9D4D
SEGMENT_LENGTH = 1024
SEGMENT_COUNT = 1
SEGMENT_COUNT_LENGTH = SEGMENT_COUNT * SEGMENT_LENGTH
SEGMENT_LENGTH_MASK = SEGMENT_LENGTH - 1
XOR_ARRAY_LENGTH = (SEGMENT_COUNT + 3) * SEGMENT_LENGTH


def rng_splitmix64(seed: int) -> int:
    z = (seed + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return z ^ (z >> 31)


def murmur64(value: int) -> int:
    value ^= value >> 33
    value = (value * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 33
    value = (value * 0xC4CEB9FE1A85EC53) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 33
    return value


def xor_fingerprint(value: int) -> int:
    return (value ^ (value >> 32)) & 0xFFFFFFFF


def parse_digest(hex_digest: str) -> bytes:
    digest = bytes.fromhex(hex_digest)
    if len(digest) != 20:
        raise ValueError("digest must be exactly 20 bytes (40 hex chars)")
    return digest


def bloom_words(digest: bytes) -> list[int]:
    return [int.from_bytes(digest[i:i + 4], "little") for i in range(0, 20, 4)]


def transformed_xor_bytes(digest: bytes) -> bytearray:
    out = bytearray(digest)
    out[3] &= out[16]
    out[7] &= out[17]
    out[11] &= out[18]
    out[15] &= out[19]
    return out


def xor_slots(item: int, seed: int) -> tuple[list[int], int]:
    hashed = murmur64((item + seed) & 0xFFFFFFFFFFFFFFFF)
    base = ((hashed * SEGMENT_COUNT_LENGTH) >> 64) & 0xFFFFFFFFFFFFFFFF
    low32 = hashed & 0xFFFFFFFF
    slots = [
        base,
        (base + SEGMENT_LENGTH) ^ ((low32 >> 18) & SEGMENT_LENGTH_MASK),
        (base + (SEGMENT_LENGTH << 1)) ^ (low32 & SEGMENT_LENGTH_MASK),
        base + SEGMENT_LENGTH * 3,
    ]
    return slots, xor_fingerprint(hashed)


def build_bloom(path: Path, digest: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    bloom = bytearray(BLOOM_SIZE)
    words = bloom_words(digest)
    values = [
        words[0], words[1], words[2], words[3], words[4],
        ((words[0] << 16) | (words[1] >> 16)) & 0xFFFFFFFF,
        ((words[1] << 16) | (words[2] >> 16)) & 0xFFFFFFFF,
        ((words[2] << 16) | (words[3] >> 16)) & 0xFFFFFFFF,
        ((words[3] << 16) | (words[4] >> 16)) & 0xFFFFFFFF,
        ((words[4] << 16) | (words[0] >> 16)) & 0xFFFFFFFF,
        ((words[0] << 8) | (words[1] >> 24)) & 0xFFFFFFFF,
        ((words[1] << 8) | (words[2] >> 24)) & 0xFFFFFFFF,
        ((words[2] << 8) | (words[3] >> 24)) & 0xFFFFFFFF,
        ((words[3] << 8) | (words[4] >> 24)) & 0xFFFFFFFF,
        ((words[4] << 8) | (words[0] >> 24)) & 0xFFFFFFFF,
        ((words[0] << 24) | (words[1] >> 8)) & 0xFFFFFFFF,
        ((words[1] << 24) | (words[2] >> 8)) & 0xFFFFFFFF,
        ((words[2] << 24) | (words[3] >> 8)) & 0xFFFFFFFF,
        ((words[3] << 24) | (words[4] >> 8)) & 0xFFFFFFFF,
        ((words[4] << 24) | (words[0] >> 8)) & 0xFFFFFFFF,
    ]
    for value in values:
        bit_index = value % (BLOOM_SIZE * 8)
        bloom[bit_index >> 3] |= 1 << (bit_index & 7)
    path.write_bytes(bloom)


def build_xor_u(path: Path, digest: bytes) -> None:
    seed = rng_splitmix64(RNG_COUNTER)
    xor_bytes = transformed_xor_bytes(digest)
    items = [
        int.from_bytes(xor_bytes[:8], "little"),
        int.from_bytes(xor_bytes[8:16], "little"),
    ]
    fingerprints = [0] * XOR_ARRAY_LENGTH

    for item in items:
        slots, rhs = xor_slots(item, seed)
        if any(slot >= XOR_ARRAY_LENGTH for slot in slots):
            raise ValueError("xor slot escaped configured array length")
        value = rhs
        for slot in slots[:-1]:
            value ^= fingerprints[slot]
        fingerprints[slots[-1]] = value

    for item in items:
        slots, rhs = xor_slots(item, seed)
        check = rhs
        for slot in slots:
            check ^= fingerprints[slot]
        if check != 0:
            raise ValueError("generated xor_u filter failed self-check")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for value in (
            1,
            XOR_ARRAY_LENGTH,
            SEGMENT_COUNT,
            SEGMENT_COUNT_LENGTH,
            SEGMENT_LENGTH,
            SEGMENT_LENGTH_MASK,
        ):
            handle.write(struct.pack("<Q", value))
        handle.write(struct.pack(f"<{XOR_ARRAY_LENGTH}I", *fingerprints))


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benchmark/test Bloom and xor_u filter fixtures for a 20-byte digest.")
    parser.add_argument("--digest", required=True, help="20-byte digest in hex")
    parser.add_argument("--bloom", help="output path for a .blf bloom filter")
    parser.add_argument("--xor-u", dest="xor_u", help="output path for a .xor_u filter")
    args = parser.parse_args()

    if not args.bloom and not args.xor_u:
        parser.error("provide at least one of --bloom or --xor-u")

    digest = parse_digest(args.digest)
    if args.bloom:
        build_bloom(Path(args.bloom), digest)
    if args.xor_u:
        build_xor_u(Path(args.xor_u), digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
