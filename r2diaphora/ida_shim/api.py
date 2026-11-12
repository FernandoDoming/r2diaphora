"""Headless implementation of the IDA ``idc``/``idaapi`` surface.

Everything here reads from an :class:`~r2diaphora.ida_shim.cache.R2BinaryCache`
that was populated by radare2 up front.  The functions are intentionally shaped
like their IDAPython counterparts (same names, same argument order, same return
types) so that unmodified Diaphora code can run against radare2 without any
source changes.

The public names are re-exported by the thin ``idc``, ``idaapi``, ``idautils``
and ``ida_*`` modules in this package; :func:`install_ida_shim` registers those
modules in ``sys.modules`` so that ``import idc`` works inside upstream code.
"""

import bisect
import importlib
import os
import re  # noqa: F401  (IDAPython's idc module leaks ``re``; upstream relies on it)
import sys
import traceback
from typing import Any, Dict, Iterable, List, Optional

from r2diaphora.ida_shim import state
from r2diaphora.ida_shim.cache import (
    capstone_operand_layout,
    _int_or_none,
    _is_padding_insn,
    _STOP_FLOW_TYPES,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BADADDR = 0xFFFFFFFFFFFFFFFF
MINADDR = 0
MAXADDR = 0xFFFFFFFFFFFFFFFF

FUNCATTR_START = 0
FUNCATTR_END = 4
FUNCATTR_FLAGS = 6

FUNC_NORET = 0x00000001
FUNC_LIB = 0x00000004
FUNC_STATICDEF = 0x00000008
FUNC_FRAME = 0x00000010
FUNC_USERFAR = 0x00000020
FUNC_HIDDEN = 0x00000040
FUNC_THUNK = 0x00000080

CIC_FUNC = 0x00000001

PRTYPE_SEMI = 0x0001
PRTYPE_CPP = 0x0002
PRTYPE_DEF = 0x0008
PRTYPE_NOARGS = 0x0010
PRTYPE_CONTAINER = 0x0020
PRTYPE_SUFFIX = 0x0040
PRTYPE_MULTI = 0x0100
PRTYPE_TYPE = 0x0200
PRTYPE_PRAGMA = 0x0400
PRTYPE_1LINE = 0x0800

OPND_OUTER = 0x00000080
OPND_ALL = 0x00000040

DP_RIGHT = 0

INF_VERSION = 4
INF_PROCNAME = 5
INF_MIN_EA = 0x10
INF_MAX_EA = 0x11
INF_SHORT_DN = 0x20

SN_CHECK = 0x0000
SN_NOCHECK = 0x0001
SN_NOWARN = 0x0002

STRTYPE_C = 0
STRTYPE_C_16 = 16

PLUGIN_MOD = 0x0001
PLUGIN_DRAW = 0x0002
PLUGIN_SEG = 0x0004
PLUGIN_UNL = 0x0008
PLUGIN_HIDE = 0x0010
PLUGIN_DBG = 0x0020
PLUGIN_PROC = 0x0040
PLUGIN_FIX = 0x0080
PLUGIN_MULTI = 0x0100

AST_ENABLE_ALWAYS = 0x0001
AST_ENABLE_FOR_IDB = 0x0002
SETMENU_APP = 0

IDA_SDK_VERSION = 920

# Decompiler flags (IDA 9.x values); the shim ignores them but upstream
# references them through ``from idaapi import *``.
DECOMP_NO_WAIT = 0x0001
DECOMP_NO_CACHE = 0x0002
DECOMP_NO_FRAME = 0x0004
DECOMP_WARNINGS = 0x0008
DECOMP_ALL_BLKS = 0x0010
DECOMP_OUT_MBA = 0x0020

o_void = 0
o_reg = 1
o_mem = 2
o_phrase = 3
o_displ = 4
o_imm = 5
o_far = 6
o_near = 7

OFFSET_OPERANDS = (o_mem, o_imm, o_far, o_near, o_displ)

DEFAULT_OPERAND_COUNT = 8


def _cache():
    return state.get_active_cache()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# cvar / batch mode
# ---------------------------------------------------------------------------


class _CVar:
    batch = True
    version = IDA_SDK_VERSION


cvar = _CVar()


# ---------------------------------------------------------------------------
# Function and instruction objects
# ---------------------------------------------------------------------------


class func_t:
    """The subset of IDA's ``func_t`` that Diaphora reads."""

    __slots__ = ("start_ea", "end_ea", "name")

    def __init__(self, start_ea: int, end_ea: int, name: str = ""):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.name = name

    def flags(self) -> int:
        return 0

    def size(self) -> int:
        return self.end_ea - self.start_ea

    def __int__(self) -> int:
        return self.start_ea

    def __repr__(self) -> str:
        return "func_t(0x%x-0x%x, %r)" % (self.start_ea, self.end_ea, self.name)


class op_t:
    __slots__ = ("type", "value", "addr", "offb", "size", "reg", "phrase", "specval")

    def __init__(self):
        self.type = o_void
        self.value = 0
        self.addr = 0
        self.offb = 0
        self.size = 0
        self.reg = 0
        self.phrase = 0
        self.specval = 0

    def __repr__(self) -> str:
        return "op_t(type=%d, value=0x%x, offb=%d)" % (self.type, self.value & 0xFFFFFFFFFFFFFFFF, self.offb)


class insn_t:
    __slots__ = ("size", "ip", "ea", "ops")

    def __init__(self):
        self.size = 0
        self.ip = BADADDR
        self.ea = BADADDR
        self.ops = [op_t() for _ in range(DEFAULT_OPERAND_COUNT)]

    def __repr__(self) -> str:
        return "insn_t(ea=0x%x, size=%d)" % (self.ea, self.size)


def _fill_insn(ins: insn_t, cached: dict) -> None:
    ins.size = int(cached.get("size") or 0)
    ea = int(cached.get("addr") or 0)
    ins.ea = ea
    ins.ip = ea
    for index, operand in enumerate(cached.get("ops") or []):
        if index >= len(ins.ops):
            break
        slot = ins.ops[index]
        slot.type = int(operand.get("type") or 0)
        slot.value = int(operand.get("value") or 0)
        slot.addr = int(operand.get("addr") or 0)
        slot.offb = int(operand.get("offb") or 0)
        slot.size = int(operand.get("size") or 0)


def decode_insn(ins: insn_t, ea: int) -> int:
    """Decode the instruction at ``ea`` into ``ins``; return its size."""
    cached = _cache().get_insn(int(ea))
    if cached is None:
        return 0
    _fill_insn(ins, cached)
    return ins.size


def decode_prev_insn(ins: insn_t, ea: int) -> int:
    cache = _cache()
    index = bisect.bisect_left(cache.sorted_insn_eas, int(ea)) - 1
    if index < 0:
        ins.ea = BADADDR
        ins.ip = BADADDR
        return 0
    return decode_insn(ins, cache.sorted_insn_eas[index])


# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------


def get_func(ea: Any) -> Optional[func_t]:
    cache = _cache()
    ea = int(ea)
    if ea in cache.functions:
        start = ea
    else:
        start = cache.get_func_ea(ea)
    if start == BADADDR or start not in cache.functions:
        return None
    info = cache.functions[start]
    return func_t(start, start + max(info["size"], 1), info["name"])


def get_next_func(ea: int) -> int:
    cache = _cache()
    index = bisect.bisect_right(cache.sorted_func_eas, int(ea))
    if index >= len(cache.sorted_func_eas):
        return BADADDR
    return cache.sorted_func_eas[index]


def get_prev_func(ea: int) -> int:
    cache = _cache()
    index = bisect.bisect_left(cache.sorted_func_eas, int(ea)) - 1
    if index < 0:
        return BADADDR
    return cache.sorted_func_eas[index]


_THUNK_JUMP_TYPES = {"jmp", "ujmp", "cjmp", "rjmp", "irjmp", "rcjmp", "ucjmp"}


def _function_flags(func) -> int:
    """Approximate IDA's function flags.

    ``FUNC_THUNK``: a single-instruction function that jumps through an IAT
    slot (e.g. ``jmp qword [imp._XcptFilter]``).  ``FUNC_LIB`` requires FLIRT
    signatures radare2 does not ship, so it is intentionally never set.

    ``FUNC_NORET``: reproduced transitively from the function's terminal
    flow transfer (named noreturn import or another noreturn function)."""
    cache = _cache()
    flags = 0
    if _func_noreturn(cache, func.start_ea, frozenset()):
        flags |= FUNC_NORET
    body = [
        cache.insns.get(ea)
        for block in cache.func_blocks.get(func.start_ea, ())
        for ea in block.get("instrs", ())
    ]
    insns = [insn for insn in body if insn is not None]
    if len(insns) != 1:
        return flags
    insn = insns[0]
    if (insn.get("type") or "") not in _THUNK_JUMP_TYPES:
        return flags
    # IDA only sets FUNC_THUNK for jumps through an import (IAT) slot; a
    # direct ``jmp <func>`` gets a ``$thunk$`` name but stays exported.
    ops = insn.get("ops") or []
    if not ops:
        return flags
    target = int(ops[0].get("value") or 0) or None
    if target is None:
        return flags
    for lo, hi in getattr(cache.pe, "iat_ranges", ()):
        if lo <= target < hi:
            flags |= FUNC_THUNK
            break
    return flags


def get_func_attr(ea: Any, attr: int, default: int = -1) -> int:
    func = get_func(ea)
    if func is None:
        return default
    if attr == FUNCATTR_START:
        return func.start_ea
    if attr == FUNCATTR_END:
        return func.end_ea
    if attr == FUNCATTR_FLAGS:
        return _function_flags(func)
    return default


def set_func_attr(ea: Any, attr: int, value: int) -> bool:
    return True


def get_func_name(ea: Any) -> str:
    cache = _cache()
    ea = int(ea)
    if ea in cache.functions:
        return cache.get_name(ea)
    start = cache.get_func_ea(ea)
    if start == BADADDR:
        return ""
    return cache.get_name(start)


def get_ea_name(ea: Any) -> str:
    return _cache().get_name(int(ea))


def get_ea_name_simple(ea: Any) -> str:
    return get_ea_name(ea)


def get_name_ea_simple(name: str) -> int:
    cache = _cache()
    for address in sorted(cache.names):
        if cache.names[address][0] == name or cache.names[address][1] == name:
            return address
    for address, info in cache.functions.items():
        if info["name"] == name:
            return address
    return BADADDR


def set_name(ea: Any, name: str, flags: int = 0) -> bool:
    _cache().names[int(ea)] = (name, name, None)
    return True


def force_name(ea: Any, name: str, flags: int = 0) -> bool:
    return set_name(ea, name, flags)


def Functions(start: Optional[int] = None, end: Optional[int] = None) -> Iterable[int]:
    cache = _cache()
    low = MINADDR if start is None else int(start)
    high = MAXADDR if end is None else int(end)
    for ea in cache.sorted_func_eas:
        if ea < low:
            continue
        if ea >= high:
            break
        yield ea


def FuncItems(func_ea: Any) -> Iterable[int]:
    cache = _cache()
    start = int(func_ea)
    if start not in cache.functions:
        inner = cache.get_func_ea(start)
        if inner == BADADDR:
            return
        start = inner
    for block in FlowChart(start):
        yield from cache.instruction_heads(block.start_ea, block.end_ea)


def Heads(start: int, end: int) -> Iterable[int]:
    return iter(_cache().instruction_heads(int(start), int(end)))


def Names() -> Iterable[Any]:
    cache = _cache()
    yielded = set()
    for ea in sorted(cache.functions):
        yielded.add(ea)
        yield ea, cache.get_name(ea)
    for ea in sorted(cache.names):
        if ea in yielded:
            continue
        name = cache.get_name(ea)
        if name:
            yield ea, name


class StringItem:
    """One entry of :class:`Strings`, mirroring ``ida_strlist.string_info_t``."""

    __slots__ = ("ea", "length", "type", "strtype", "_text")

    def __init__(self, ea: int, length: int, strtype: int, text: str):
        self.ea = ea
        self.length = length
        self.type = strtype
        self.strtype = strtype
        self._text = text

    def __str__(self) -> str:
        return self._text

    def __len__(self) -> int:
        return len(self._text)

    def __repr__(self) -> str:
        return "StringItem(0x%x, %r)" % (self.ea, self._text)


class Strings:
    """The ``idautils.Strings`` enumerator used by ``IDAMagicStrings``."""

    def __init__(self, default_setup: bool = True):
        self._strtypes: List[int] = [STRTYPE_C]
        self._minlen = 5
        self._items: Optional[List[StringItem]] = None
        if default_setup:
            self.setup()

    def setup(self, strtypes=None, minlen: int = 5, only_7bit: bool = True,
              ignore_heads: bool = False) -> bool:
        if strtypes:
            self._strtypes = [int(value) for value in strtypes]
        self._items = None
        return True

    def _build(self) -> List[StringItem]:
        items: List[StringItem] = []
        for ea in sorted(_cache().strings_by_ea):
            entry = _cache().strings_by_ea[ea]
            text = entry.get("string") or ""
            if not isinstance(text, str):
                text = str(text)
            size = int(entry.get("length") or 0) or (len(text) + 1)
            items.append(StringItem(ea, size, get_str_type(ea), text))
        return items

    def __iter__(self):
        if self._items is None:
            self._items = self._build()
        return iter(self._items)

    def __len__(self) -> int:
        if self._items is None:
            self._items = self._build()
        return len(self._items)

    def refresh(self) -> None:
        self._items = None

    def clear(self) -> None:
        self._items = None


# ---------------------------------------------------------------------------
# Cross references
# ---------------------------------------------------------------------------


def CodeRefsFrom(ea: Any, flow: int = 0) -> Iterable[int]:
    return iter(_cache().get_code_refs_from(int(ea), int(flow)))


def CodeRefsTo(ea: Any, flow: int = 0) -> Iterable[int]:
    return iter(_cache().get_code_refs_to(int(ea), int(flow)))


def DataRefsFrom(ea: Any) -> Iterable[int]:
    return iter(_cache().get_data_refs_from(int(ea)))


def DataRefsTo(ea: Any) -> Iterable[int]:
    return iter(_cache().data_refs_to.get(int(ea), []))


# ---------------------------------------------------------------------------
# Instructions and operands
# ---------------------------------------------------------------------------


def get_item_size(ea: Any) -> int:
    cached = _cache().get_insn(int(ea))
    return int(cached.get("size") or 0) if cached else 0


def get_bytes(ea: Any, size: int, use_dbg: bool = False) -> bytes:
    return _cache().get_bytes(int(ea), int(size))


def get_byte(ea: Any) -> int:
    data = _cache().get_bytes(int(ea), 1)
    return data[0] if data else -1


def get_wide_byte(ea: Any) -> int:
    return get_byte(ea)


def patch_byte(ea: Any, value: int) -> bool:
    return False


def get_many_bytes(ea: Any, size: int) -> bytes:
    return get_bytes(ea, size)


def GetManyBytes(ea: Any, size: int, use_dbg: bool = False) -> bytes:
    return get_bytes(ea, size, use_dbg)


def get_operand_value(ea: Any, n: int) -> int:
    """Return ``insn.ops[n].value`` or ``BADADDR`` when there is no such operand."""
    cached = _cache().get_insn(int(ea))
    if not cached:
        return BADADDR
    operands = cached.get("ops") or []
    if n < 0 or n >= len(operands):
        return BADADDR
    operand = operands[n]
    if int(operand.get("type") or 0) == o_void:
        return BADADDR
    return int(operand.get("value") or 0) & 0xFFFFFFFFFFFFFFFF


def GetOperandValue(ea: Any, n: int) -> int:
    return get_operand_value(ea, n)


# radare2 -> IDA canonical mnemonics.  IDA prints the primary Intel name for
# conditional instructions (jz/jnb/cmovz/setz...) while radare2 often emits an
# alias (je/jae/cmove/sete...); normalizing keeps the mnemonics list, the
# small-primes product and the instructions table identical to IDA's.
_CONDITION_CODE_CANONICAL = {
    "e": "z",
    "ne": "nz",
    "ae": "nb",
    "be": "be",
    "a": "a",
    "b": "b",
    "s": "s",
    "ns": "ns",
    "p": "p",
    "np": "np",
    "pe": "p",
    "po": "np",
    "l": "l",
    "ge": "ge",
    "le": "le",
    "g": "g",
    "o": "o",
    "no": "no",
    "nbe": "a",
    "na": "be",
    "nge": "l",
    "nl": "ge",
    "nle": "g",
    "ng": "le",
    "c": "b",
    "nc": "nb",
    "nae": "b",
}

_MNEMONIC_CANONICAL = {
    "ret": "retn",
    "movabs": "mov",
    "sal": "shl",
    "wait": "fwait",
    "xlatb": "xlat",
}


def canonical_mnemonic(mnemonic: str) -> str:
    """Translate a radare2 mnemonic to IDA's canonical spelling."""
    if not mnemonic:
        return mnemonic
    direct = _MNEMONIC_CANONICAL.get(mnemonic)
    if direct is not None:
        return direct
    for prefix in ("cmov", "set", "loop", "j"):
        if mnemonic.startswith(prefix):
            suffix = mnemonic[len(prefix) :]
            canonical = _CONDITION_CODE_CANONICAL.get(suffix)
            if canonical is not None:
                return prefix + canonical
            break
    return mnemonic


def print_insn_mnem(ea: Any) -> str:
    cached = _cache().get_insn(int(ea))
    if not cached:
        return ""
    mnemonic = cached.get("mnemonic") or (cached.get("disasm") or "").split(" ")[0]
    return canonical_mnemonic(mnemonic)


def GetMnem(ea: Any) -> str:
    return print_insn_mnem(ea)


def print_operand(ea: Any, n: int) -> str:
    cached = _cache().get_insn(int(ea))
    if not cached:
        return ""
    operands = cached.get("ops") or []
    if n < 0 or n >= len(operands):
        return ""
    operand = operands[n]
    kind = operand.get("type")
    if kind == o_void:
        return ""
    if kind == o_reg:
        return operand.get("reg") or ""
    value = int(operand.get("value") or 0)
    if kind in (o_mem, o_near, o_far):
        name = _cache().get_name(value)
        if name:
            return name
        return "0x%x" % (value & 0xFFFFFFFFFFFFFFFF)
    if kind in (o_imm, o_displ):
        return "0x%x" % (value & 0xFFFFFFFFFFFFFFFF)
    return ""


def GetDisasm(ea: Any) -> str:
    cached = _cache().get_insn(int(ea))
    return (cached.get("disasm") or "") if cached else ""


def generate_disasm_line(ea: Any, flags: int = 0) -> str:
    cached = _cache().get_insn(int(ea))
    return (cached.get("disasm") or "") if cached else ""


def GetString(ea: Any, length: int = -1, strtype: int = -1) -> str:
    data = get_strlit_contents(ea, length, strtype)
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "backslashreplace")
    return str(data)


def GetCommentEx(ea: Any, repeatable: int = 0) -> Optional[str]:
    return _cache().comments_by_ea.get(int(ea))


def get_cmt(ea: Any, repeatable: int = 0) -> Optional[str]:
    return GetCommentEx(ea, repeatable)


def set_cmt(ea: Any, comment: str, repeatable: int = 0) -> None:
    _cache().comments_by_ea[int(ea)] = comment


def get_func_cmt(ea: Any, repeatable: int = 0) -> str:
    cache = _cache()
    func = get_func(ea)
    if func is None:
        return ""
    return cache.comments_by_ea.get(func.start_ea, "") or ""


def set_func_cmt(ea: Any, comment: str, repeatable: int = 0) -> bool:
    func = get_func(ea)
    if func is None:
        return False
    _cache().comments_by_ea[func.start_ea] = comment
    return True


# ---------------------------------------------------------------------------
# Global information
# ---------------------------------------------------------------------------


def get_inf_attr(attr: int) -> int:
    cache = _cache()
    if attr == INF_MIN_EA:
        return cache.min_ea
    if attr == INF_MAX_EA:
        return cache.max_ea
    if attr == INF_VERSION:
        return IDA_SDK_VERSION
    if attr == INF_PROCNAME:
        return cache.idp_name
    return 0


def get_imagebase() -> int:
    return _cache().image_base


def get_idp_name() -> str:
    return _cache().idp_name


def get_arch() -> str:
    return _cache().arch


def get_idb_path() -> str:
    return _cache().input_path


def get_root_filename() -> str:
    return os.path.basename(_cache().input_path)


def GetInputFileMD5() -> bytes:
    """Like IDA's GetInputFileMD5: the raw 16-byte digest, not hex text."""
    return bytes.fromhex(_cache().md5sum)


def get_fileregion_offset(ea: Any) -> int:
    return -1


def is_mapped(ea: Any) -> bool:
    return _cache().is_mapped(int(ea))


def is_spec_ea(ea: Any) -> bool:
    return False


def is_loaded(ea: Any) -> bool:
    return is_mapped(ea)


def get_flags(ea: Any) -> int:
    return 0


def get_flags32(ea: Any) -> int:
    return 0


def has_auto_name(flags: int) -> bool:
    return False


def has_dummy_name(flags: int) -> bool:
    return False


def is_forced_operand(ea: Any, n: int) -> bool:
    return False


def get_forced_operand(ea: Any, n: int) -> str:
    return ""


def set_forced_operand(ea: Any, n: int, text: str) -> bool:
    return False


# ---------------------------------------------------------------------------
# Segments
# ---------------------------------------------------------------------------


class segment_t:
    __slots__ = ("start_ea", "end_ea", "name", "perm")

    def __init__(self, start_ea: int, end_ea: int, name: str, perm: str = ""):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.name = name
        self.perm = perm


def segment_for(ea: Any) -> Optional[dict]:
    return _cache().get_segment_for(int(ea))


def get_segm_start(ea: Any) -> int:
    segment = segment_for(ea)
    return segment["vaddr"] if segment else 0


def get_segm_end(ea: Any) -> int:
    segment = segment_for(ea)
    return (segment["vaddr"] + segment["vsize"]) if segment else 0


def get_segm_name(ea: Any) -> str:
    segment = segment_for(ea)
    return segment["name"] if segment else ""


def get_segm_by_name(name: str) -> Optional[segment_t]:
    for segment in _cache().segments:
        if segment["name"].lower() == str(name).lower():
            return segment_t(
                segment["vaddr"],
                segment["vaddr"] + segment["vsize"],
                segment["name"],
                segment.get("perm", ""),
            )
    return None


def SegStart(ea: Any) -> int:
    return get_segm_start(ea)


def SegEnd(ea: Any) -> int:
    return get_segm_end(ea)


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


def _string_entry(ea: int) -> Optional[dict]:
    return _cache().strings_by_ea.get(int(ea))


def _string_bytes(entry: dict, strtype: int = -1) -> bytes:
    text = entry.get("string", "")
    if not isinstance(text, str):
        text = str(text)
    wide = strtype == STRTYPE_C_16 or entry.get("type") in ("utf16", "utf-16", "unicode")
    if wide:
        return text.encode("utf-16-le", "surrogatepass")
    return text.encode("utf-8", "backslashreplace")


def get_str_type(ea: Any) -> int:
    entry = _string_entry(int(ea))
    if entry and entry.get("type") in ("utf16", "utf-16", "unicode"):
        return STRTYPE_C_16
    return STRTYPE_C


def get_max_strlit_length(ea: Any, strtype: int = STRTYPE_C) -> int:
    entry = _string_entry(int(ea))
    if entry is None:
        if strtype in (STRTYPE_C, -1):
            data = _literal_bytes(int(ea))
            return len(data) + 1 if data else 0
        return 0
    if strtype == STRTYPE_C_16 and get_str_type(ea) != STRTYPE_C_16:
        return 0
    if strtype == STRTYPE_C and get_str_type(ea) == STRTYPE_C_16:
        return 0
    return len(_string_bytes(entry, strtype)) + 1


_STRLIT_CHARS = frozenset(list(range(0x20, 0x7F)) + [0x09, 0x0A, 0x0B, 0x0C, 0x0D])


def _literal_bytes(ea: int) -> Optional[bytes]:
    """Best-effort emulation of IDA's ``get_strlit_contents`` on a mapped
    address that is not a defined string: it scans the raw bytes and returns
    the leading run of C-string characters (printable plus the usual escape
    whitespace), or ``None`` when the first byte cannot start a literal or
    the item looks like an offset into the image.
    """
    cache = _cache()
    if not cache.is_mapped(ea):
        return None
    raw = cache.get_bytes(ea, 64)
    if len(raw) >= 4 and (
        cache.is_mapped(int.from_bytes(raw[:4], "little"))
        or cache.is_mapped(int.from_bytes(raw[:8], "little"))
    ):
        return None
    # UTF-16LE literal: a run of ``<printable> 00`` pairs.  MSVC keeps switch
    # names and format strings (``"fo"``, ``"%s"``) wide, and IDA's
    # ``get_strlit_contents`` returns their decoded text rather than stopping
    # at the first interleaved NUL.
    if (
        len(raw) >= 4
        and raw[0] in _STRLIT_CHARS
        and raw[1] == 0
        and raw[2] in _STRLIT_CHARS
        and raw[3] == 0
    ):
        out = bytearray()
        for index in range(0, len(raw) - 1, 2):
            if raw[index] not in _STRLIT_CHARS or raw[index + 1] != 0:
                break
            out.append(raw[index])
        return bytes(out) if out else None
    out = bytearray()
    for byte in raw:
        if byte not in _STRLIT_CHARS:
            break
        out.append(byte)
    return bytes(out) if out else None


_C_ESCAPES = {
    ord("a"): 0x07,
    ord("b"): 0x08,
    ord("f"): 0x0C,
    ord("n"): 0x0A,
    ord("r"): 0x0D,
    ord("t"): 0x09,
    ord("v"): 0x0B,
    ord("?"): ord("?"),
    ord("\\"): ord("\\"),
    ord("'"): ord("'"),
    ord('"'): ord('"'),
}


def _unescape_literal(data: bytes) -> bytes:
    """Interpret C escape sequences the way ``get_strlit_contents`` does: a
    string item that reads ``\\\\VarFileInfo\\\\`` in the image is the
    literal ``\\VarFileInfo\\``.  Unknown escapes keep their backslash."""
    if b"\\" not in data:
        return data
    out = bytearray()
    index = 0
    size = len(data)
    while index < size:
        byte = data[index]
        if byte != 0x5C or index + 1 >= size:
            out.append(byte)
            index += 1
            continue
        nxt = data[index + 1]
        if nxt in _C_ESCAPES:
            out.append(_C_ESCAPES[nxt])
            index += 2
        elif nxt == ord("x"):
            digits = []
            pos = index + 2
            while pos < size and chr(data[pos]) in "0123456789abcdefABCDEF":
                digits.append(data[pos])
                pos += 1
            if digits:
                out.append(int(bytes(digits), 16) & 0xFF)
                index = pos
            else:
                out.append(byte)
                index += 1
        elif ord("0") <= nxt <= ord("7"):
            pos = index + 1
            digits = []
            while pos < size and len(digits) < 3 and ord("0") <= data[pos] <= ord("7"):
                digits.append(data[pos])
                pos += 1
            out.append(int(bytes(digits), 8) & 0xFF)
            index = pos
        else:
            out.append(byte)
            index += 1
    return bytes(out)


def get_strlit_contents(ea: Any, length: int = -1, strtype: int = -1) -> Optional[bytes]:
    entry = _string_entry(int(ea))
    if entry is not None:
        data = _string_bytes(entry, strtype)
    else:
        data = _literal_bytes(int(ea))
    if data is None:
        return None
    data = _unescape_literal(data)
    if length is not None and length > 0:
        data = data[: int(length)]
    return data


def GetStrLitContents(ea: Any) -> bytes:
    data = get_strlit_contents(ea, -1, -1)
    return data if data is not None else b""


def tag_remove(line: str) -> str:
    from r2diaphora.ida_shim.cache import strip_ansi

    return strip_ansi(line or "")


def get_sourcefile(ea: Any) -> Optional[str]:
    return None


# ---------------------------------------------------------------------------
# Types / misc IDA registry APIs
# ---------------------------------------------------------------------------


def get_type(ea: Any) -> str:
    return ""


def SetType(ea: Any, type: str) -> bool:
    return True


def guess_type(ea: Any) -> str:
    return ""


def GuessType(ea: Any) -> str:
    return ""


def parse_decls(text: str, flags: int = 0) -> int:
    return 0


def get_numbered_type_name(ordinal: int) -> str:
    return ""


def get_ordinal_qty() -> int:
    return 0


def get_ordinal_count() -> int:
    return 0


def get_local_tinfo(ordinal: int):
    return None


def idc_print_type(stype: Any, fields: Any, name: str, flags: int = 0) -> str:
    return ""


def add_default_til(name: str) -> bool:
    return True


def get_struc_id(name: str) -> int:
    return BADADDR


def get_struc_name(sid: int) -> str:
    return ""


def GetLocalTypeName(ordinal: int) -> str:
    return ""


def GetMaxLocalType() -> int:
    return 0


def get_switch_info(ea: Any):
    return None


def calc_switch_cases(ea: Any, switch: Any):
    return None


def demangle_name(name: str, flags: int = 0) -> Optional[str]:
    return None


def get_config_value(name: str) -> str:
    return ""


def inf_get_short_demnames() -> int:
    return 0


def is_main_thread() -> bool:
    return True


def register_timer(*args, **kwargs) -> int:
    return 0


def unregister_timer(*args, **kwargs) -> bool:
    return True


def is_call_insn(ins: insn_t) -> bool:
    cached = _cache().get_insn(int(getattr(ins, "ea", BADADDR)))
    if not cached:
        return False
    return (cached.get("type") or "") in (
        "call",
        "ucall",
        "icall",
        "rcall",
        "ircall",
        "swi",
    )


def get_instruction_list():
    from r2diaphora.idaapi.instructions import CPU_INSTRUCTIONS

    return CPU_INSTRUCTIONS.get(_cache().arch, [])


def GetInstructionList():
    return get_instruction_list()


def init_hexrays_plugin(flags: int = 0) -> bool:
    """IDAPython exposes this convenience wrapper from ``idaapi``."""
    from r2diaphora.ida_shim import ida_hexrays

    return ida_hexrays.init_hexrays_plugin(flags)


def decompile(ea_or_func: Any, flags: int = 0):
    """IDAPython's ``idaapi.decompile`` helper."""
    from r2diaphora.ida_shim import ida_hexrays

    return ida_hexrays.decompile(ea_or_func, flags)


# ---------------------------------------------------------------------------
# UI / plugin stubs (headless: everything is a no-op)
# ---------------------------------------------------------------------------


def msg(text: str) -> None:
    return None


def warning(text: str) -> None:
    sys.stderr.write("%s\n" % (text,))


def info(text: str) -> None:
    sys.stderr.write("%s\n" % (text,))


def show_wait_box(text: str = "") -> None:
    return None


def hide_wait_box() -> None:
    return None


def replace_wait_box(text: str = "") -> None:
    return None


def auto_wait() -> None:
    return None


def user_cancelled() -> bool:
    return False


class Choose:
    """Headless stand-in for ``ida_kernwin.Choose``.

    Upstream Diaphora subclasses this to build interactive choosers.  In
    batch mode nothing is ever shown, so the UI methods are inert and
    :meth:`Show` simply reports success.
    """

    CHCOL_PLAIN = 0x00000000
    CHCOL_PATH = 0x00000001
    CH_MULTI = 0x00000001
    CH_NOIDB = 0x00000002
    ALL_CHANGED = 0
    EMPTY_CHOOSER = 0
    NEW_CHOOSER = 1

    def __init__(self, title="", columns=None, flags=0):
        self.title = title
        self.columns = columns or []
        self.flags = flags
        self.items = []
        self.selected_items = []

    def Show(self, modal=False):
        return 0

    def Close(self, *args, **kwargs):
        return None

    def Refresh(self, *args, **kwargs):
        return None

    def add_item(self, item):
        self.items.append(item)
        return len(self.items) - 1

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, sel):
        return None

    def OnDeleteLine(self, sel):
        return [self.ALL_CHANGED] + list(sel)

    def OnPopup(self, widget, popup_handle):
        return None


def ask_yn(*args, **kwargs) -> int:
    return 1


def ask_file(*args, **kwargs):
    return None


def jumpto(ea: Any, *args, **kwargs) -> None:
    return None


def set_dock_pos(*args, **kwargs) -> None:
    return None


def set_color(ea: Any, what: int, color: int) -> None:
    return None


def find_widget(title: str):
    return None


def get_widget_title(widget: Any) -> str:
    return ""


def is_dark_mode() -> bool:
    return False


def activate_widget(widget: Any, take_focus: bool) -> bool:
    return False


def process_ui_action(name: str, flags: int = 0) -> bool:
    return False


def request_refresh(*args, **kwargs) -> None:
    return None


def qexit(code: int = 0) -> None:
    return None


def reg_read_string(name: str, default: str = "") -> str:
    return default


def load_plugin(name: str) -> bool:
    return False


def restore_user_cmts(ea: Any):
    return None


def clear_cached_cfuncs() -> None:
    if state.has_active_cache():
        state.get_active_cache().decompiled.clear()


def require(name: str):
    return importlib.import_module(name)


class action_handler_t:
    def __init__(self):
        pass

    def activate(self, ctx):
        return 0

    def update(self, ctx):
        return 0


class action_desc_t:
    def __init__(self, name="", label="", handler=None, shortcut=None, tooltip=None, icon=-1):
        self.name = name
        self.label = label
        self.handler = handler
        self.shortcut = shortcut
        self.tooltip = tooltip
        self.icon = icon


def register_action(desc) -> bool:
    return True


def unregister_action(name: str) -> bool:
    return True


def attach_action_to_menu(menu_path: str, name: str, flags: int = 0) -> bool:
    return True


def attach_action_to_popup(widget, popup_handle, name, flags: int = 0) -> bool:
    return True


def attach_dynamic_action_to_popup(widget, popup_handle, desc, flags: int = 0) -> bool:
    return True


class treeloc_t:
    def __init__(self):
        self.ea = BADADDR
        self.itp = 0
        self.level = 0


class Form:
    def __init__(self, *args, **kwargs):
        pass

    def Show(self, *args, **kwargs) -> int:
        return 0

    def Close(self, *args, **kwargs) -> None:
        return None


class PluginForm(Form):
    def OnCreate(self, form):
        return 0

    def OnClose(self, form):
        return None


class GraphViewer:
    def __init__(self, *args, **kwargs):
        pass

    def Show(self, *args, **kwargs) -> bool:
        return False

    def Close(self, *args, **kwargs) -> None:
        return None

    def AddNode(self, *args, **kwargs) -> int:
        return -1

    def AddEdge(self, *args, **kwargs) -> bool:
        return False

    def Clear(self) -> None:
        return None

    def Refresh(self) -> None:
        return None

    def SetNodes(self, *args, **kwargs) -> None:
        return None

    def SetEdge(self, *args, **kwargs) -> None:
        return None


class View_Hooks:
    def __init__(self, *args, **kwargs):
        pass


class plugin_t:
    flags = 0
    comment = ""
    help = ""
    wanted_name = ""
    wanted_hotkey = ""

    def init(self):
        return 0

    def run(self, arg):
        return None

    def term(self):
        return None


class plugmod_t:
    def __init__(self, *args, **kwargs):
        pass


class _Loader:
    """Lazy loader used for the module objects registered in sys.modules."""

    def __init__(self, module_name: str):
        self.module_name = module_name

    def __getattr__(self, name):
        module = importlib.import_module(self.module_name)
        return getattr(module, name)


def get_graph_viewer(widget):
    return None


def viewer_set_gli(*args, **kwargs) -> None:
    return None


# ---------------------------------------------------------------------------
# Control flow graph
# ---------------------------------------------------------------------------


class BasicBlock:
    """The subset of IDA's ``BasicBlock`` that Diaphora uses."""

    __slots__ = ("id", "start_ea", "end_ea", "_succs", "_preds")

    def __init__(self, block_id: int, start_ea: int, end_ea: int):
        self.id = block_id
        self.start_ea = start_ea
        self.end_ea = end_ea
        self._succs: List["BasicBlock"] = []
        self._preds: List["BasicBlock"] = []

    def succs(self):
        return iter(self._succs)

    def preds(self):
        return iter(self._preds)

    def __repr__(self) -> str:
        return "BasicBlock(0x%x-0x%x)" % (self.start_ea, self.end_ea)


# radare2 instruction types whose terminating instruction makes a basic block
# noreturn (``int 0x29``/``ud2``): IDA gives such blocks no successors.
_NORETURN_TYPES = frozenset({"swi", "ill"})
# radare2 instruction types for unconditional jumps out of the function.
_JMP_OUT_TYPES = frozenset({"jmp", "ujmp", "ijmp", "rjmp", "irjmp"})
# radare2 call mnemonics; an ``int3`` right after one marks a noreturn call.
_CALL_TYPES = frozenset({"call", "ucall", "icall", "rcall", "ircall"})

# Callee name suffixes IDA knows never return (CRT/process termination).
_NORETURN_SUFFIXES = (
    "_exit",
    "exit",
    "abort",
    "terminate",
    "invoke_watson",
    "_watson",
    "fatalappexita",
    "fatalappexitw",
    "fatalappexit",
    "fatalexit",
    "raisefailfastexception",
    "fastfail",
    "longjmp",
    "longjmpex",
    "cxxthrowexception",
    "endthread",
    "endthreadex",
    "exitprocess",
    "exitthread",
    "rtlexituserthread",
    "terminateprocess",
)


def _is_noreturn_name(name: str) -> bool:
    """Match ``sym.imp.msvcrt.dll__exit``/``_terminate__YAXXZ``-style callee
    names against IDA's noreturn functions."""
    base = (name or "").lower().split("dll_")[-1].split(".")[-1].split("@")[0]
    if not base.startswith("__"):
        base = base.split("__")[0]
    return any(base.endswith(suffix) for suffix in _NORETURN_SUFFIXES)


def _func_noreturn(cache, ea: int, seen: frozenset) -> bool:
    """Return True when the function at ``ea`` can never return.

    IDA sets ``FUNC_NORET`` by analysis; reproduce it transitively: a
    function with no ``ret`` whose last flow transfer lands on a noreturn
    target (named import, or another noreturn function) is noreturn.
    """
    memo = getattr(cache, "_noreturn_memo", None)
    if memo is None:
        memo = cache._noreturn_memo = {}
    if ea in memo:
        return memo[ea]
    info = cache.functions.get(ea)
    result = False
    computed = info is not None and ea not in seen
    if computed:
        seen = seen | {ea}
        flow_insn = None
        has_ret = False
        for block in cache.func_blocks.get(ea, ()):
            for head in cache.instruction_heads(
                int(block["addr"]), int(block["addr"]) + int(block["size"])
            ):
                insn = cache.insns.get(head)
                if insn is None:
                    continue
                itype = insn.get("type") or ""
                if itype in ("ret", "iret", "rret"):
                    has_ret = True
                elif itype in _CALL_TYPES or itype in _JMP_OUT_TYPES:
                    flow_insn = insn
                    if itype in _CALL_TYPES and _noreturn_call(
                        cache, insn, seen
                    ):
                        # Code after a call that cannot return is dead; a
                        # ``ret`` in it does not make the function returning.
                        break
        if not has_ret and flow_insn is not None:
            target = _int_or_none(flow_insn.get("jump")) or _int_or_none(
                flow_insn.get("ptr")
            )
            result = target is not None and (
                _is_noreturn_name(cache.get_name(target))
                or _is_noreturn_name(cache.get_true_name(target))
                or _func_noreturn(cache, target, seen)
            )
    if computed:
        memo[ea] = result
    return result


def _noreturn_call(cache, insn: dict, seen: frozenset = frozenset()) -> bool:
    if (insn.get("type") or "") not in _CALL_TYPES:
        return False
    target = _int_or_none(insn.get("jump")) or _int_or_none(insn.get("ptr"))
    if target is None:
        return False
    return (
        _is_noreturn_name(cache.get_name(target))
        or _is_noreturn_name(cache.get_true_name(target))
        or _func_noreturn(cache, target, seen)
    )


def _tail_instruction(cache, start: int, end: int) -> Optional[dict]:
    """Last non-padding instruction of a basic block (int3 filler skipped)."""
    for head in reversed(cache.instruction_heads(start, end)):
        insn = cache.insns.get(head)
        if insn is not None and insn.get("type") != "trap":
            return insn
    return None


def _truncate_block_end(cache, start: int, end: int, func_end: int) -> int:
    """Clip a block's end after its first flow-barrier instruction.

    radare2 folds dead padding into basic blocks (``int3``/``nop`` fillers
    after ``ret``/``jmp`` and after noreturn calls); IDA stops the block at
    the barrier, so the padding is never a ``FuncItem``.  A padding tail is
    dropped only when every instruction after it through the function's end
    is padding too: between live blocks a ``nop`` is a real instruction IDA
    counts.
    """
    heads = cache.instruction_heads(start, end)
    limit = end
    pad_start = len(heads)
    for index in range(len(heads) - 1, -1, -1):
        insn = cache.insns.get(heads[index])
        if insn is not None and _is_padding_insn(insn):
            pad_start = index
        else:
            break
    if pad_start < len(heads):
        rest = cache.instruction_heads(heads[pad_start], func_end)
        if all(
            _is_padding_insn(cache.insns.get(head) or {})
            for head in rest
        ):
            limit = heads[pad_start]
    for index, head in enumerate(heads):
        insn = cache.insns.get(head)
        if insn is None:
            continue
        itype = insn.get("type") or ""
        if itype in _STOP_FLOW_TYPES:
            return min(head + int(insn.get("size") or 0), limit)
        if itype in _CALL_TYPES and index + 1 < len(heads):
            nxt = cache.insns.get(heads[index + 1])
            if nxt is not None and (nxt.get("type") or "") == "trap":
                return min(head + int(insn.get("size") or 0), limit)
    return limit


def _executable_ea(cache, ea: int) -> bool:
    segment = cache.get_segment_for(ea)
    return segment is not None and "x" in segment.get("perm", "")


def _split_blocks(raw_blocks: List[dict], split_points: set) -> List[dict]:
    """Split raw agfj blocks at SEH scope boundaries, like IDA's FlowChart."""
    out = []
    for block in sorted(raw_blocks, key=lambda item: item["addr"]):
        start = int(block["addr"])
        cuts = sorted(
            point
            for point in split_points
            if start < point < start + max(int(block["size"]), 0)
        )
        cursor = start
        for cut in cuts:
            piece = dict(block)
            piece["addr"] = cursor
            piece["size"] = cut - cursor
            piece["jump"] = None
            piece["fail"] = cut
            out.append(piece)
            cursor = cut
        tail = dict(block)
        tail["addr"] = cursor
        tail["size"] = start + int(block["size"]) - cursor
        out.append(tail)
    return out


def FlowChart(func) -> List[BasicBlock]:
    cache = _cache()
    start = getattr(func, "start_ea", func)
    try:
        start = int(start)
    except (TypeError, ValueError):
        return []
    raw_blocks = cache.get_blocks(start)
    if not raw_blocks:
        info = cache.functions.get(start)
        if info is None:
            return []
        raw_blocks = [
            {
                "addr": start,
                "size": max(info["size"], 1),
                "jump": None,
                "fail": None,
                "ninstr": info["ninstrs"],
            }
        ]
    else:
        raw_blocks = [dict(block) for block in raw_blocks]

    # IDA models SEH try scopes and funclets in the flow graph; radare2's
    # ``afbj`` does not.  Reproduce IDA's shape from the ``try.*`` flags the
    # cache recovered from PE exception data and the C++ EH IP-to-state map
    # boundaries parsed from ``.pdata``: try-region starts, filter entries and
    # every EH state-transition address are block boundaries, and the block
    # that starts a try region gains an edge to the filter funclet (catch
    # blocks stay orphaned, as IDA).
    regions = cache.try_regions.get(start) or {}
    split_points = set(cache.eh_boundaries.get(start) or ())
    for region in regions.values():
        for key in ("from", "filter"):
            ea = region.get(key)
            if ea:
                split_points.add(ea)
    # FH4 state transitions split only when the same straight-line run
    # contains a call: the call can throw, so the post-call state starts a
    # new block in IDA's chart.  Transitions mid-run stay invisible.
    block_starts = sorted(int(b["addr"]) for b in raw_blocks)
    for va in cache.eh_transitions.get(start) or ():
        idx = bisect.bisect_right(block_starts, va) - 1
        if idx < 0:
            continue
        for head in cache.instruction_heads(block_starts[idx], va):
            insn = cache.insns.get(head)
            if insn is not None and (insn.get("type") or "") == "call":
                split_points.add(va)
                break
    # A boundary that does not land on a decoded instruction is metadata
    # noise (padding, alignment); splitting there creates empty blocks.
    split_points &= {va for va in split_points if va in cache.insns}
    if split_points:
        raw_blocks = _split_blocks(raw_blocks, split_points)

    for raw in raw_blocks:
        block_start = int(raw["addr"])
        tail = _tail_instruction(cache, block_start, block_start + int(raw["size"]))
        if tail is None:
            continue
        tail_type = tail.get("type") or ""
        if tail_type in _JMP_OUT_TYPES:
            # A block ending in a jump never falls through; radare2 still
            # reports ``fail`` pointing past the tail, which would fabricate
            # an external pseudo node.
            raw["fail"] = None
        elif tail_type in _NORETURN_TYPES or _noreturn_call(cache, tail):
            raw["jump"] = None
            raw["fail"] = None
            raw["noreturn"] = True

    blocks: List[BasicBlock] = []
    kept_raws: List[dict] = []
    by_addr: Dict[int, BasicBlock] = {}
    dropped: List[Tuple[int, int]] = []
    func_end = max(
        int(block["addr"]) + max(int(block["size"]), 1) for block in raw_blocks
    )
    for block in raw_blocks:
        block_start = int(block["addr"])
        raw_end = block_start + max(int(block["size"]), 1)
        block_end = _truncate_block_end(
            cache, block_start, raw_end, func_end
        )
        heads = (
            cache.instruction_heads(block_start, block_end)
            if block_end > block_start
            else []
        )
        if not heads or all(
            _is_padding_insn(cache.insns.get(head) or {}) for head in heads
        ):
            # IDA never makes a basic block out of pure padding.
            dropped.append((block_start, raw_end))
            continue
        block_obj = BasicBlock(len(blocks), block_start, block_end)
        blocks.append(block_obj)
        kept_raws.append(block)
        by_addr[block_start] = block_obj
    drop_starts = [span[0] for span in dropped]

    pseudos: Dict[int, BasicBlock] = {}

    def _link(source: BasicBlock, target: Optional[int]) -> None:
        if target is None:
            return
        target = int(target)
        target_block = by_addr.get(target)
        if target_block is None:
            index = bisect.bisect_right(drop_starts, target) - 1
            if (
                index >= 0
                and dropped[index][0] <= target < dropped[index][1]
            ):
                return  # edge into a pad-only piece: dead code, no edge
            # A flow successor outside the function's blocks is an external
            # node in IDA's chart: a zero-width block that owns no instructions.
            target_block = pseudos.get(target)
            if target_block is None:
                target_block = BasicBlock(len(blocks) + len(pseudos), target, target)
                pseudos[target] = target_block
        if target_block not in source._succs:
            source._succs.append(target_block)
            target_block._preds.append(source)

    extra_edges: Dict[int, List[int]] = {}
    for region in regions.values():
        if region.get("from") and region.get("filter"):
            extra_edges.setdefault(region["from"], []).append(region["filter"])

    for block, raw in zip(blocks, kept_raws):
        for key in ("fail", "jump"):
            _link(block, raw.get(key))
        for target in extra_edges.get(int(raw["addr"]), ()):
            _link(block, target)
        if raw.get("jump") is None and raw.get("fail") is None and not raw.get("noreturn"):
            tail = _tail_instruction(
                cache, int(raw["addr"]), int(raw["addr"]) + int(raw["size"])
            )
            if tail is not None and (tail.get("type") or "") in _JMP_OUT_TYPES:
                target = _int_or_none(tail.get("jump"))
                if target is None:
                    pointer = _int_or_none(tail.get("ptr"))
                    if pointer is not None:
                        width = max(cache.bits // 8, 4)
                        raw_ptr = cache.get_bytes(pointer, width)
                        if raw_ptr:
                            resolved = int.from_bytes(raw_ptr, "little")
                            if _executable_ea(cache, resolved):
                                target = resolved
                elif not _executable_ea(cache, target):
                    target = None
                _link(block, target)

    # IDA links a catch funclet's epilogue block back to the funclet entry
    # and forward to the continuation address its ``lea`` loads for the EH
    # dispatcher; radare2 models the same bytes as a plain ``ret``.
    if start in cache.eh_catch and blocks:
        last = max(blocks, key=lambda blk: blk.end_ea)
        lea_targets = []
        for head in cache.instruction_heads(last.start_ea, last.end_ea):
            insn = cache.insns.get(head)
            if insn is None or (insn.get("type") or "") != "lea":
                continue
            target = _int_or_none(insn.get("ptr"))
            if (
                target is not None
                and _executable_ea(cache, target)
                and not start <= target < last.end_ea
            ):
                lea_targets.append(target)
        if lea_targets:
            _link(last, start)
            for target in lea_targets:
                _link(last, target)

    # IDA orders each block's edge lists by the successor's position in the
    # chart (creation order), so a backward branch precedes the fallthrough.
    for block in blocks + list(pseudos.values()):
        block._succs.sort(key=lambda succ: succ.id)
        block._preds.sort(key=lambda pred: pred.id)

    chart = blocks + list(pseudos.values())
    if chart and start in cache.synthesized:
        # A synthesized funclet owns only the blocks reachable from its
        # entry; pieces the entry's flow never reaches belong to other
        # funclets (or no function) in IDA's ownership model. Real
        # functions keep every owned block: IDA includes unreachable
        # landing pads and dead chunks in their charts.
        entry = next(
            (
                block
                for block in chart
                if block.start_ea <= start < block.end_ea
            ),
            chart[0],
        )
        reachable = set()
        work = [entry]
        while work:
            node = work.pop()
            if node in reachable:
                continue
            reachable.add(node)
            work.extend(node._succs)
        pruned = [block for block in chart if block in reachable]
        if len(pruned) != len(chart):
            kept = set(pruned)
            for block in pruned:
                block._succs = [succ for succ in block._succs if succ in kept]
                block._preds = [pred for pred in block._preds if pred in kept]
            for index, block in enumerate(pruned):
                block.id = index
            chart = pruned
    return chart

# ---------------------------------------------------------------------------
# Hex-Rays names re-exported by `idaapi` in IDAPython
# ---------------------------------------------------------------------------

CV_FAST = 0x0001

# IDAPython's `idaapi` historically leaks the Hex-Rays ctree visitor so that
# `from idaapi import *` is enough to subclass it.  Importing it here keeps
# that contract without any upstream change.
from r2diaphora.ida_shim.ida_hexrays import ctree_visitor_t  # noqa: E402,F401
