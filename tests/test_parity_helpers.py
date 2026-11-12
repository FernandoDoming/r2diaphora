"""Regression tests for the IDA-parity helpers added during the whoami.exe
comparison drive.  These exercise the pure seams of the shim - no radare2
or IDA process is required.
"""

from types import SimpleNamespace

import pytest

from r2diaphora.ida_shim import api, state
from r2diaphora.ida_shim.cache import R2BinaryCache, _is_padding_insn


class _StubCache:
    """Minimal stand-in for the pieces of ``R2BinaryCache`` the pure
    helpers touch."""

    def __init__(self):
        self.functions = {}
        self.func_blocks = {}
        self.insns = {}
        self.strings_by_ea = {}
        self.names = {}
        self.pe = SimpleNamespace(iat_ranges=[])

    def instruction_heads(self, start, end):
        return sorted(ea for ea in self.insns if start <= ea < end)

    def get_name(self, ea):
        return self.names.get(ea)

    def get_true_name(self, ea):
        return self.names.get(ea)

    def is_mapped(self, ea):
        # Anything above this bound is unmapped, so the pointer-detection
        # heuristic in _literal_bytes does not treat literal bytes as an
        # offset into the image.
        return 0 < ea < 0x10000

    def get_bytes(self, ea, size):
        return self._raw.get(ea, b"")[:size]

    _raw = {}


def test_is_noreturn_name_matches_import_suffixes():
    assert api._is_noreturn_name("sym.imp.msvcrt.dll__exit")
    assert api._is_noreturn_name("sym.imp.msvcrt.dll__cexit")
    assert api._is_noreturn_name("_terminate__YAXXZ")
    assert api._is_noreturn_name("kernel32.dll_TerminateProcess")
    assert not api._is_noreturn_name("sym.imp.msvcrt.dll__wfopen")
    assert not api._is_noreturn_name("wmain")


def _func(cache, ea, insns):
    """Register a single-block function ending at the last insn."""
    cache.functions[ea] = {"size": insns[-1]["addr"] + insns[-1]["size"] - ea}
    cache.func_blocks[ea] = [
        {"addr": ea, "size": insns[-1]["addr"] + insns[-1]["size"] - ea}
    ]
    for insn in insns:
        cache.insns[insn["addr"]] = insn


def test_func_noreturn_false_when_function_returns():
    cache = _StubCache()
    _func(
        cache,
        0x1000,
        [
            {"addr": 0x1000, "size": 1, "type": "mov"},
            {"addr": 0x1001, "size": 1, "type": "ret"},
        ],
    )
    assert api._func_noreturn(cache, 0x1000, frozenset()) is False


def test_func_noreturn_through_named_import():
    cache = _StubCache()
    cache.names[0x2000] = "sym.imp.msvcrt.dll__exit"
    _func(
        cache,
        0x1000,
        [
            {"addr": 0x1000, "size": 5, "type": "call", "jump": 0x2000},
            {"addr": 0x1005, "size": 1, "type": "ret"},  # dead code
        ],
    )
    # The ret sits after a call that cannot return; the function is noreturn.
    assert api._func_noreturn(cache, 0x1000, frozenset()) is True


def test_func_noreturn_propagates_transitively():
    cache = _StubCache()
    cache.names[0x3000] = "sym.imp.msvcrt.dll_abort"
    _func(
        cache,
        0x2000,
        [{"addr": 0x2000, "size": 5, "type": "call", "jump": 0x3000}],
    )
    _func(
        cache,
        0x1000,
        [{"addr": 0x1000, "size": 5, "type": "jmp", "jump": 0x2000}],
    )
    assert api._func_noreturn(cache, 0x2000, frozenset()) is True
    assert api._func_noreturn(cache, 0x1000, frozenset()) is True


def test_func_noreturn_call_cycle_terminates():
    cache = _StubCache()
    _func(
        cache,
        0x1000,
        [{"addr": 0x1000, "size": 5, "type": "call", "jump": 0x2000}],
    )
    _func(
        cache,
        0x2000,
        [{"addr": 0x2000, "size": 5, "type": "call", "jump": 0x1000}],
    )
    # Mutually recursive calls with no reachable exit: not noreturn, and
    # crucially the evaluation must terminate.
    assert api._func_noreturn(cache, 0x1000, frozenset()) is False
    assert api._func_noreturn(cache, 0x2000, frozenset()) is False


def test_func_noreturn_cycle_does_not_poison_memo():
    cache = _StubCache()
    cache.names[0x9000] = "sym.imp.msvcrt.dll__exit"
    # 0x2000 calls back into 0x1000 (cycle) and then into _exit; once the
    # cycle member is skipped the _exit call decides the result.
    _func(
        cache,
        0x1000,
        [{"addr": 0x1000, "size": 5, "type": "call", "jump": 0x2000}],
    )
    _func(
        cache,
        0x2000,
        [
            {"addr": 0x2000, "size": 5, "type": "call", "jump": 0x1000},
            {"addr": 0x2005, "size": 5, "type": "call", "jump": 0x9000},
        ],
    )
    assert api._func_noreturn(cache, 0x1000, frozenset()) is True
    assert api._func_noreturn(cache, 0x2000, frozenset()) is True


def test_unescape_literal_handles_c_escapes():
    assert api._unescape_literal(b"\\\\VarFileInfo\\\\Translation") == (
        b"\\VarFileInfo\\Translation"
    )
    assert api._unescape_literal(b"a\\nb\\tc") == b"a\nb\tc"
    assert api._unescape_literal(b"\\x41") == b"A"
    # C semantics: \x consumes hex digits greedily and truncates to a byte.
    assert api._unescape_literal(b"\\x41bc") == b"\xbc"
    assert api._unescape_literal(b"\\101") == b"A"
    # Unknown escapes keep their backslash.
    assert api._unescape_literal(b"\\q") == b"\\q"
    assert api._unescape_literal(b"plain") == b"plain"


def test_is_padding_insn():
    assert _is_padding_insn({"type": "nop", "bytes": "90"})
    assert _is_padding_insn({"type": "trap", "bytes": "cc"})
    assert _is_padding_insn({"type": "invalid", "bytes": "cc"})
    assert not _is_padding_insn({"type": "mov", "bytes": "4889c8"})
    assert not _is_padding_insn({"type": "ret", "bytes": "c3"})


def test_is_iat_thunk():
    cache = _StubCache()
    cache.pe.iat_ranges = [(0x14000F000, 0x14000F100)]
    thunk = {
        "addr": 0x140001EE0,
        "type": "jmp",
        "ops": [{"value": 0x14000F020}],
    }
    assert R2BinaryCache._is_iat_thunk(cache, thunk) is True
    direct = {"addr": 0x140001EE0, "type": "jmp", "ops": [{"value": 0x140002000}]}
    assert R2BinaryCache._is_iat_thunk(cache, direct) is False
    not_jump = {"addr": 0x140001EE0, "type": "mov", "ops": [{"value": 0x14000F020}]}
    assert R2BinaryCache._is_iat_thunk(cache, not_jump) is False
    no_ops = {"addr": 0x140001EE0, "type": "jmp", "ops": []}
    assert R2BinaryCache._is_iat_thunk(cache, no_ops) is False


def test_get_strlit_contents_decodes_utf16_literal():
    cache = _StubCache()
    cache._raw = {0x5000: b"f\x00o\x00\x00\x00"}
    state.set_active_cache(cache)
    try:
        assert api.get_strlit_contents(0x5000) == b"fo"
    finally:
        state.set_active_cache(None)


def test_get_strlit_contents_unescapes_image_bytes():
    cache = _StubCache()
    cache._raw = {0x6000: b"\\\\VarFileInfo\\\\Translation\x00"}
    state.set_active_cache(cache)
    try:
        assert api.get_strlit_contents(0x6000) == b"\\VarFileInfo\\Translation"
    finally:
        state.set_active_cache(None)
