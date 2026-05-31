#!/usr/bin/env python3
"""Patch integrity placeholders in the built PE (.text/.rdata/.idata SHA-256)."""
from __future__ import annotations

import hashlib
import struct
import sys

TEXT_PLACEHOLDER = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 8)
RDATA_PLACEHOLDER = bytes([0xBA, 0xAD, 0xF0, 0x0D] * 8)
IDATA_PLACEHOLDER = bytes([0xFE, 0xED, 0xFA, 0xCE] * 8)
ITHASH_PLACEHOLDER = IDATA_PLACEHOLDER


def find_section(pe: bytes, name: bytes) -> tuple[int, int]:
    if pe[:2] != b"MZ":
        raise ValueError("not a PE file")
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if struct.unpack_from("<I", pe, e_lfanew)[0] != 0x4550:
        raise ValueError("invalid PE signature")

    file_header = e_lfanew + 4
    num_sections = struct.unpack_from("<H", pe, file_header + 2)[0]
    optional_header_size = struct.unpack_from("<H", pe, file_header + 16)[0]
    section_table = file_header + 20 + optional_header_size

    for index in range(num_sections):
        entry = section_table + index * 40
        sec_name = pe[entry : entry + 8].rstrip(b"\x00")
        if sec_name != name:
            continue
        virtual_size, _, raw_size, raw_ptr = struct.unpack_from("<IIII", pe, entry + 8)
        return raw_ptr, min(raw_size, virtual_size) if raw_size else virtual_size

    raise ValueError(f"{name.decode(errors='ignore')} section not found")


def find_placeholder_offset(pe: bytes, needle: bytes, required: bool = True) -> int | None:
    offset = pe.find(needle)
    if offset == -1:
        if required:
            raise RuntimeError("placeholder not found in PE")
        return None
    count = pe.count(needle)
    if count != 1:
        raise RuntimeError(f"expected 1 placeholder, found {count}")
    return offset


def patch_exe(path: str) -> int:
    raw = bytearray(open(path, "rb").read())

    text_start, text_size = find_section(raw, b".text")
    rdata_start, rdata_size = find_section(raw, b".rdata")

    text_digest = hashlib.sha256(bytes(raw[text_start : text_start + text_size])).digest()
    rdata_digest = hashlib.sha256(bytes(raw[rdata_start : rdata_start + rdata_size])).digest()

    try:
        idata_start, idata_size = find_section(raw, b".idata")
        idata_digest = hashlib.sha256(bytes(raw[idata_start : idata_start + idata_size])).digest()
    except ValueError:
        idata_digest = None

    off_text = find_placeholder_offset(raw, TEXT_PLACEHOLDER, required=False)
    off_rdata = find_placeholder_offset(raw, RDATA_PLACEHOLDER, required=False)
    off_ithash = find_placeholder_offset(raw, ITHASH_PLACEHOLDER, required=False)

    if off_text is not None:
        raw[off_text : off_text + 32] = text_digest
    else:
        print("patch_text_sha256: .text placeholder not found, skipping .text patch")

    if off_rdata is not None:
        raw[off_rdata : off_rdata + 32] = rdata_digest
    else:
        print("patch_text_sha256: .rdata placeholder not found, skipping .rdata patch")

    if idata_digest is not None:
        if off_ithash is not None:
            raw[off_ithash : off_ithash + 32] = idata_digest
        else:
            print("patch_text_sha256: .ithash placeholder not found, skipping .ithash patch")

    with open(path, "wb") as handle:
        handle.write(raw)

    print(f"patch_text_sha256: {path}")
    print(f"  .text  -> {text_digest.hex()}")
    print(f"  .rdata -> {rdata_digest.hex()}")
    if idata_digest is not None:
        print(f"  .idata -> {idata_digest.hex()}")
    else:
        print("  .idata -> (not found, left as placeholder)")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-exe>", file=sys.stderr)
        return 2
    return patch_exe(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
