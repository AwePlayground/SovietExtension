#!/usr/bin/env python3
"""Check verified 270135 profile entries against the supplied arm64 image."""

import re
import struct
import sys
import uuid
from pathlib import Path


EXPECTED_UUID = uuid.UUID("0c2f01c0-c197-3286-901d-70e1d007a1c0")
EXPECTED_ENTRY = bytes.fromhex("fc6fbda9f44f01a9fd7b02a9fd830091")
EXPECTED_OPEN_URL_ENTRY = bytes.fromhex("ff8307d1fc6f1aa9f6571ba9f44f1ca9")
EXPECTED_MULTI_OPEN_ENTRY = bytes.fromhex("ff0306d1fc6f14a9f65715a9f44f16a9")
EXPECTED_FORWARD_ENTRIES = (
    bytes.fromhex("ffc301d1f85f03a9f65704a9f44f05a9"),
    bytes.fromhex("f44fbea9fd7b01a9fd430091f30300aa"),
    bytes.fromhex("ff4306d1fc6f13a9fa6714a9f85f15a9"),
    bytes.fromhex("ff8301d1f85f02a9f65703a9f44f04a9"),
)
SOURCE = Path(__file__).resolve().parents[1] / "SovietExtension" / "SovietExtension" / "RevokePatch.mm"


def arm64_image(path):
    data = Path(path).read_bytes()
    if data[:4] == bytes.fromhex("cafebabe"):
        count = struct.unpack_from(">I", data, 4)[0]
        for index in range(count):
            cpu, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + index * 20)
            if cpu == 0x100000C:
                image = data[offset : offset + size]
                break
        else:
            raise AssertionError("arm64 slice not found")
    else:
        image = data
    assert struct.unpack_from("<I", image)[0] == 0xFEEDFACF
    assert struct.unpack_from("<I", image, 4)[0] == 0x100000C, "expected arm64 Mach O"
    commands = struct.unpack_from("<I", image, 16)[0]
    position = 32
    image_uuid = None
    for _ in range(commands):
        command, size = struct.unpack_from("<II", image, position)
        if command == 0x1B:
            image_uuid = uuid.UUID(bytes=image[position + 8 : position + 24])
        position += size
    assert image_uuid == EXPECTED_UUID, f"unexpected arm64 UUID: {image_uuid}"
    return image


def field(profile, name):
    match = re.search(r"\." + re.escape(name) + r"\s*=\s*(0x[0-9a-fA-F]+|\d+)", profile)
    assert match, f"profile field {name} missing"
    return int(match.group(1), 0)


def branch_target(image, address):
    instruction = struct.unpack_from("<I", image, address)[0]
    assert instruction & 0xFC000000 == 0x94000000, f"expected BL at {address:#x}"
    displacement = instruction & 0x03FFFFFF
    if displacement & (1 << 25):
        displacement -= 1 << 26
    return address + displacement * 4


def template_address(image, entry):
    pc = entry + 0x1C
    adrp, add = struct.unpack_from("<II", image, pc)
    assert adrp & 0x9F000000 == 0x90000000
    assert add & 0xFFC00000 == 0x91000000
    pages = (((adrp >> 5) & 0x7FFFF) << 2) | ((adrp >> 29) & 3)
    if pages & (1 << 20):
        pages -= 1 << 21
    return (pc & ~0xFFF) + pages * 4096 + ((add >> 10) & 0xFFF)


def main():
    assert len(sys.argv) == 2, "usage: check_wechat_270135_profile.py wechat.dylib"
    image = arm64_image(sys.argv[1])
    source = SOURCE.read_text()
    marker = '.buildVersion = "270135"'
    assert marker in source, "Build 270135 profile missing"
    start = source.rfind(".displayName =", 0, source.index(marker))
    end = source.index("\n    },", source.index(marker))
    profile = source[start:end]

    assert ".hookMode = YMRevokeHookModeV415Callsite" in profile
    assert "ok = YMPatchRevokeOriginV415((uintptr_t)slide);" in source
    assert "if (profile->hookMode == YMRevokeHookModeV415Callsite) {\n        return profile->revokeOriginCallsiteAfterQueryVA != 0" in source
    entry = field(profile, "hookPointerVA")
    assert image[entry : entry + 16] == EXPECTED_ENTRY, "revoke entry fingerprint changed"
    assert struct.unpack_from("<I", image, entry + 0x28)[0] == 0x52804F02, "wrap length is not 632"
    assert field(profile, "messageWrapSize") == 632
    assert field(profile, "rawMessageTemplateVA") == template_address(image, entry)
    assert field(profile, "messageWrapFromRawVA") == branch_target(image, entry + 0x38)
    assert field(profile, "messageWrapDestructVA") == branch_target(image, entry + 0x4C)

    insert = field(profile, "insertPaySysMsgToSessionVA")
    assert struct.unpack_from("<I", image, insert + 0x4C)[0] == 0x5284E201, "notice insert routine changed"
    assert "YMMatchesWeChat270135RevokeDylib" in source, "runtime binary guard missing"
    browser_entry = field(profile, "openURLWebViewKindVA")
    assert image[browser_entry : browser_entry + 16] == EXPECTED_OPEN_URL_ENTRY, "system browser entry changed"
    assert "YMMatchesWeChat270135OpenURLDylib" in source, "system browser runtime guard missing"
    multi_open_entry = field(profile, "YMMultiOpenTryPreventMultiInstanceVA")
    assert image[multi_open_entry : multi_open_entry + 16] == EXPECTED_MULTI_OPEN_ENTRY, "multi open entry changed"
    assert struct.unpack_from("<I", image, multi_open_entry + 0x2C)[0] == 0x52800000
    assert image[multi_open_entry + 0x34 : multi_open_entry + 0x38] == bytes.fromhex("20060036")
    assert "YMMatchesWeChat270135MultiOpenDylib" in source, "multi open runtime guard missing"
    forward = re.search(r"\.mediaForward\s*=\s*\{([^}]+)\}", profile)
    assert forward, "native forwarding entries missing"
    forward_addresses = [int(value.strip(), 0) for value in forward.group(1).split(",")]
    assert len(forward_addresses) == 4
    for address, expected in zip(forward_addresses, EXPECTED_FORWARD_ENTRIES):
        assert image[address : address + 16] == expected, f"forwarding entry changed at {address:#x}"
    assert struct.unpack_from("<I", image, forward_addresses[0] + 0x30)[0] == 0x52806A02
    assert struct.unpack_from("<I", image, forward_addresses[0] + 0x1B4)[0] == 0x9102E260
    assert struct.unpack_from("<I", image, forward_addresses[0] + 0x1F4)[0] == 0x9104C281
    assert struct.unpack_from("<I", image, forward_addresses[1] + 0x10)[0] == 0xF9419800
    assert field(profile, "messageDataConstructVA") == 0x4D59134
    assert image[0x4D59134 : 0x4D59144] == bytes.fromhex("e88a02b008411891084100911f700278")
    assert struct.unpack_from("<I", image, 0x4D59200)[0] == 0xB9034008
    assert field(profile, "accountGetterVA") == branch_target(image, insert + 0x10C)
    assert image[field(profile, "accountGetterVA") : field(profile, "accountGetterVA") + 12] == bytes.fromhex(
        "a8ef0290009d47f9c0035fd6"
    )
    assert "YMMatchesWeChat270135ForwardDylib" in source, "native forwarding runtime guard missing"
    callsite = field(profile, "revokeOriginCallsiteAfterQueryVA")
    assert branch_target(image, 0x31E55BC) == 0x35373C8, "revoke entry origin query changed"
    assert callsite == 0x31E55C0, "revoke entry origin query callsite moved"
    assert image[callsite : callsite + 16] == bytes.fromhex(
        "f46f41f9740100b48822009109008092"
    ), "origin query continuation changed"
    assert field(profile, "revokeOriginCallsiteContinueVA") == callsite + 16
    assert field(profile, "revokeOriginCallsiteZeroBranchVA") == 0x31E55F0
    assert field(profile, "revokeOriginOutWrapStackOffset") == 0x50
    assert struct.unpack_from("<I", image, 0x31E5650)[0] == 0x394B23E8, "origin optional flag moved"
    assert "YMRevokeOriginCallsiteModeV415" in source, "270135 origin continuation missing"
    assert "[RevokeCallsite] 270135 retained revoke system origin" in source
    assert branch_target(image, 0x3537F98) == 0x31B68F8, "inner original query changed"
    assert image[0x3537F9C : 0x3537FAC] == bytes.fromhex(
        "f68741f9760100b4c822009109008092"
    ), "inner original query continuation changed"
    assert struct.unpack_from("<I", image, 0x353802C)[0] == 0x394AC3E8
    assert "YMRevoke270135InnerCallsiteStub" in source
    wrap = re.search(r"rawWrap\[(\d+)\]", source)
    assert wrap and int(wrap.group(1)) >= 632, "temporary MessageWrap storage is too small"
    room_query = field(profile, "roomNameQueryVA")
    assert room_query == 0x4338914, "270135 room query entry is not adapted"
    assert image[room_query : room_query + 32] == bytes.fromhex(
        "f657bda9f44f01a9fd7b02a9fd830091ffc309d1f30302aaf40301aae0e30091"
    ), "room query ABI entry changed"
    assert branch_target(image, room_query + 0x17C) == 0x3EDAC8, "room query session copy changed"
    assert image[0x3EDAEC : 0x3EDAF4] == bytes.fromhex("6082049181820491"), "room name offset changed"
    assert "YMMatchesWeChat270135RevokeDylib()" in source[source.index("YMRoomNameQueryRuntimeAddress"):], (
        "270135 room query runtime guard missing"
    )
    print("Build 270135 verified profile entries match the supplied arm64 image")


if __name__ == "__main__":
    main()
