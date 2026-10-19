#!/usr/bin/env python3
"""Verify every native sidebar entry before enabling the 270135 patch."""

import re
import hashlib
import struct
import sys
import uuid
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "SovietExtension" / "SovietExtension" / "SidebarRuntime.h"
EXPECTED_UUID = uuid.UUID("0c2f01c0-c197-3286-901d-70e1d007a1c0")


def arm64_image(path):
    data = Path(path).read_bytes()
    if data[:4] == bytes.fromhex("cafebabe"):
        count = struct.unpack_from(">I", data, 4)[0]
        for index in range(count):
            cpu, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + index * 20)
            if cpu == 0x100000C:
                data = data[offset : offset + size]
                break
        else:
            raise AssertionError("arm64 slice missing")
    assert struct.unpack_from("<I", data)[0] == 0xFEEDFACF
    commands = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    for _ in range(commands):
        command, size = struct.unpack_from("<II", data, cursor)
        if command == 0x1B:
            assert uuid.UUID(bytes=data[cursor + 8 : cursor + 24]) == EXPECTED_UUID
            break
        cursor += size
    else:
        raise AssertionError("Mach O UUID missing")
    return data


def branch_target(image, address):
    instruction = struct.unpack_from("<I", image, address)[0]
    assert instruction & 0xFC000000 == 0x94000000
    displacement = instruction & 0x03FFFFFF
    if displacement & (1 << 25):
        displacement -= 1 << 26
    return address + displacement * 4


def main():
    assert len(sys.argv) == 2, "usage: check_sidebar_270135_profile.py wechat.dylib"
    assert str(Path(sys.argv[1]).resolve()).endswith(
        "/WeChat.app/Contents/Resources/wechat.dylib"
    ), "sidebar preflight requires an app named WeChat.app"
    image = arm64_image(sys.argv[1])
    source = SOURCE.read_text()
    start = source.index("YMNavigationSidebarWeChat415BuildProfile = {")
    end = source.index("};", start)
    profile = source[start:end]
    assert '"4.1.15"' in profile and '"270135"' in profile
    uuid_block = re.search(r'"arm64",\s*\{([^}]+)\}', profile)
    assert uuid_block
    profile_uuid = bytes(int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]{2}", uuid_block.group(1)))
    assert profile_uuid == EXPECTED_UUID.bytes, "profile UUID differs from the binary"
    target_start = source.index("YMSidebarPatchWeChat415TargetProfile = {")
    target = source[target_start : source.index("0x170,", target_start)]
    digest_block = re.search(r'&YMNavigationSidebarWeChat415BuildProfile,\s*\{([^}]+)\}', target)
    assert digest_block
    digest = bytes(int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]{2}", digest_block.group(1)))
    assert digest == hashlib.sha256(Path(sys.argv[1]).read_bytes()).digest(), (
        "profile SHA-256 differs from the on-disk binary"
    )
    pairs = re.findall(r"(0x[0-9A-Fa-f]+),\s*\{([^}]+)\}", profile)
    assert len(pairs) == 24, f"expected 24 native entries, found {len(pairs)}"
    for address_text, fingerprint_text in pairs:
        address = int(address_text, 16)
        fingerprint = bytes(int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]{2}", fingerprint_text))
        assert len(fingerprint) == 16, f"bad fingerprint at {address:#x}"
        assert image[address : address + 16] == fingerprint, f"fingerprint mismatch at {address:#x}"
    assert struct.unpack_from("<I", image, 0x121429C)[0] == 0x39482008, "layout mode offset changed"
    assert struct.unpack_from("<I", image, 0x1214420)[0] == 0x91084260, "overflow offset changed"
    assert struct.unpack_from("<I", image, 0x12144C0)[0] == 0xF940CA60, "secondary controller offset changed"
    assert struct.unpack_from("<I", image, 0x1217D4C)[0] == 0xF940C000, "primary controller offset changed"
    assert branch_target(image, 0x1217D50) == 0x1FBF1DC, "native primary selector changed"
    assert image[0x10EBCD4 : 0x10EBCDC] == bytes.fromhex("002840b9c0035fd6")
    print("Build 270135 sidebar profile matches all 24 native entries")


if __name__ == "__main__":
    main()
