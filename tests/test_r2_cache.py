import struct

import pytest

from r2diaphora.ida_shim.cache import (
    R2BinaryCache,
    capstone_operand_layout,
    parse_pdata_entries,
)

CALC = r"C:\Windows\System32\calc.exe"


def test_parse_pdata_entries_skips_zero_padding_and_non_exec():
    # Review Focus #2: 4096-byte .pdata with valid entries followed by 0s
    image_base = 0x140000000
    exec_ranges = [(0x140001000, 0x140003000)]
    raw = (
        struct.pack("<III", 0x1010, 0x1084, 0x38E8)
        + struct.pack("<III", 0x14C0, 0x1731, 0x3848)
        + struct.pack("<III", 0x3100, 0x3120, 0x3850)  # outside exec_ranges (.rdata)
        + b"\x00" * 120
    )
    starts = parse_pdata_entries(raw, image_base, exec_ranges)
    assert starts == [0x140001010, 0x1400014C0]


def test_capstone_operand_layout_matches_ida_offb():
    # decoded_size in Diaphora is size - offb(op0) - offb(op1); IDA's offb is the
    # byte offset of the immediate / displacement field inside the instruction.
    def offb(code_hex):
        layout = capstone_operand_layout(bytes.fromhex(code_hex))
        return [] if layout is None else [op["offb"] for op in layout]

    assert offb("4883ec18") == [0, 3]  # sub rsp, 0x18
    assert offb("488d41ff") == [0, 3]  # lea rax, [rcx - 1]
    assert offb("4883f8fd") == [0, 3]  # cmp rax, -3
    assert offb("b84d5a0000") == [0, 1]  # mov eax, 0x5a4d
    assert offb("488b0528000000") == [0, 3]  # mov rax, [rip + 0x28]
    assert offb("e8fbfeffff") == [1]  # call rel32
    assert offb("ffffffff") == [] or len(offb("ffffffff")) == 0  # invalid bytes


def test_capstone_operand_layout_classifies_operand_types():
    layout = capstone_operand_layout(bytes.fromhex("488b0528000000"))  # mov rax, [rip+0x28]
    assert layout[0]["type"] == 1  # o_reg
    assert layout[1]["type"] == 2  # o_mem (rip-relative is absolute in IDA)
    layout = capstone_operand_layout(bytes.fromhex("488d41ff"))  # lea rax, [rcx-1]
    assert layout[1]["type"] == 4  # o_displ
    layout = capstone_operand_layout(bytes.fromhex("488b01"))  # mov rax, [rcx]
    assert layout[1]["type"] == 3  # o_phrase


def test_r2_binary_cache_on_calc_exe():
    cache = R2BinaryCache(CALC, load_pdb=False)
    try:
        assert cache.image_base == 0x140000000
        assert cache.idp_name == "metapc"
        assert cache.bits == 64
        assert cache.md5sum == "18e5b970eab39020b7e53aa81c371287"
        # .pdata seeding must discover _tlgEnableCallback (0x140001010) and __wmainCRTStartup (0x1400014c0)
        assert 0x140001010 in cache.functions
        assert 0x1400014C0 in cache.functions
        assert 0x1400017CC in cache.functions
        assert 0x1400019D4 in cache.functions
        # Entry0 (0x140001740) must be 18 bytes (not 598 merged into __wmainCRTStartup)
        assert cache.functions[0x140001740]["size"] == 18
        assert cache.functions[0x140001740]["name"] == "entry0"

        cache.ensure_function_cached(0x1400017CC)
        cmds_before = cache.cmd_count
        insn = cache.get_insn(0x1400017CC)
        assert insn is not None
        assert insn["mnemonic"] == "sub"
        assert insn["size"] == 4
        assert insn["decoded_size"] <= insn["size"]
        assert cache.get_bytes(0x1400017CC, 4) == bytes.fromhex("4883ec18")
        # Zero r2 calls during instruction/byte lookup
        assert cache.cmd_count == cmds_before

        # mov eax, 0x5a4d at 0x1400017dc: IDA subtracts offb=1 -> decoded_size 4
        insn = cache.get_insn(0x1400017DC)
        assert insn["decoded_size"] == 4
        # lea rax, [rcx-1] at 0x1400017d2: offb=3 -> decoded_size 1
        insn = cache.get_insn(0x1400017D2)
        assert insn["decoded_size"] == 1

        # Names are normalized out of radare2's flag namespace
        assert cache.get_name(0x140001740) == "entry0"
        assert cache.get_name(0x1400017CC).startswith("sub_")
        # Calls are code refs
        assert 0x140001138 in cache.get_code_refs_from(0x140001744)
        # Strings indexed by address
        assert cache.strings_by_ea
        assert any(len(entry["string"]) > 0 for entry in cache.strings_by_ea.values())
    finally:
        cache.close()


def test_calc_blocks_and_edges_match_diaphora_shape():
    cache = R2BinaryCache(CALC, load_pdb=False)
    try:
        blocks = cache.get_blocks(0x1400017CC)
        assert len(blocks) == 8
        assert sum(b["ninstr"] for b in blocks) == 25
        assert all(b["addr"] < b["addr"] + b["size"] for b in blocks)
    finally:
        cache.close()
