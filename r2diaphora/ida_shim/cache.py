"""One-shot radare2 binary cache.

Everything the Diaphora exporter needs is fetched from radare2 in a small,
fixed number of batch invocations: one process for the binary-wide metadata
plus control-flow graphs, and one process per chunk of functions to analyze
every instruction.  After the caches are built, all ``idc``/``idaapi`` lookups
are served from memory, so the per-instruction export path performs no IPC at
all.

Why ``-i script`` and not ``r2pipe``: radare2 6.x on Windows answers the
``-0`` pipe handshake and then emits an ANSI cursor-position query
(``ESC[6n``) that a plain pipe never answers, so every command hangs.  Running
one script per phase is also faster: the whole of ``calc.exe`` is dumped in
about 0.2 seconds.
"""

import bisect
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

SECTION_PREFIX = "R2DIA:SECTION:"
DEFAULT_CHUNK_SIZE = 1500

# IDA operand types (values are part of the on-disk compatibility contract).
O_VOID = 0
O_REG = 1
O_MEM = 2
O_PHRASE = 3
O_DISPL = 4
O_IMM = 5
O_FAR = 6
O_NEAR = 7

_FLOW_INSTRUCTION_TYPES = frozenset(
    {
        "call",
        "ucall",
        "icall",
        "rcall",
        "jmp",
        "ujmp",
        "ijmp",
        "rjmp",
        "cjmp",
        "ret",
        "trap",
    }
)

# radare2 instruction types that do not pass control flow to the next
# instruction (used to emulate IDA's ``flow`` flag on code references).
_STOP_FLOW_TYPES = frozenset(
    {
        "jmp",
        "ujmp",
        "ijmp",
        "rjmp",
        "ret",
        "hlt",
        "ill",
        "invalid",
        "trap",
        "int3",
    }
)

# Instruction types that end a function: unconditional jumps out, returns,
# and traps.  Gap-split functions must end on one of these.
_TERMINAL_TYPES = frozenset(
    {
        "jmp",
        "ujmp",
        "ijmp",
        "rjmp",
        "irjmp",
        "ret",
        "iret",
        "rret",
        "hlt",
        "ill",
        "invalid",
        "trap",
        "int3",
    }
)

_JMP_TYPES = frozenset(
    {"jmp", "ujmp", "ijmp", "rjmp", "irjmp", "rcjmp", "ucjmp"}
)

_CALL_TYPES = frozenset({"call", "ucall", "icall", "rcall", "ircall"})

OFFSET_OPERAND_TYPES = (O_MEM, O_IMM, O_FAR, O_NEAR, O_DISPL)

_NAME_PREFIXES = ("sym.imp.", "sym.", "imp.")

_CS_ENGINES: Dict[Tuple[int, bool], Any] = {}
_CS_AVAILABLE: Optional[bool] = None


def find_r2_binary(name: str = "radare2") -> Optional[str]:
    """Locate the radare2 executable, including the usual Windows install."""
    for candidate in (name + ".exe", name):
        found = shutil.which(candidate)
        if found:
            return found
    for env_var in ("R2_HOME", "RADARE2_HOME"):
        base = os.environ.get(env_var)
        if base:
            for candidate in ("radare2.exe", "radare2"):
                path = os.path.join(base, "bin", candidate)
                if os.path.isfile(path):
                    return path
    for guess in (
        os.path.expandvars(r"%USERPROFILE%\tools\radare2\bin\radare2.exe"),
        r"C:\radare2\bin\radare2.exe",
        "/usr/local/bin/radare2",
        "/usr/bin/radare2",
    ):
        if os.path.isfile(guess):
            return guess
    return None


class PEInfo:
    """Minimal PE parser: image base, sections and the executable ranges."""

    def __init__(
        self,
        image_base: int,
        sections: List[dict],
        uninit_ranges: Optional[List[Tuple[int, int]]] = None,
        iat_ranges: Optional[List[Tuple[int, int]]] = None,
    ):
        self.image_base = image_base
        self.sections = sections
        self.uninit_ranges = uninit_ranges or []
        self.iat_ranges = iat_ranges or []

    @property
    def exec_ranges(self) -> List[Tuple[int, int]]:
        return [(s["vaddr"], s["vaddr"] + s["vsize"]) for s in self.sections if s["exec"]]

    def section(self, name: str) -> Optional[dict]:
        for section in self.sections:
            if section["name"].lower() == name.lower():
                return section
        return None

    def read_section(self, path: str, name: str) -> Optional[bytes]:
        section = self.section(name)
        if section is None:
            return None
        with open(path, "rb") as handle:
            handle.seek(section["paddr"])
            return handle.read(min(section["size"], section["vsize"]))


def parse_pe(path: str) -> Optional[PEInfo]:
    try:
        with open(path, "rb") as handle:
            data = handle.read(0x1000)
    except OSError:
        return None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return None
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        size_opt = struct.unpack_from("<H", data, pe_offset + 20)[0]
        opt = pe_offset + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == 0x20B:
            image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        elif magic == 0x10B:
            image_base = struct.unpack_from("<I", data, opt + 28)[0]
        else:
            return None
        sections = []
        table = opt + size_opt
        for index in range(num_sections):
            raw = data[table + index * 40 : table + (index + 1) * 40]
            if len(raw) < 40:
                break
            name = raw[:8].split(b"\0")[0].decode("ascii", "replace")
            vsize, vaddr, size, paddr = struct.unpack_from("<IIII", raw, 8)
            characteristics = struct.unpack_from("<I", raw, 36)[0]
            sections.append(
                {
                    "name": name,
                    "vsize": vsize,
                    "vaddr": image_base + vaddr,
                    "size": size,
                    "paddr": paddr,
                    "exec": bool(characteristics & 0x20000000),
                }
            )
        # Ranges IDA treats as uninitialized: the IAT directory (the loader
        # overwrites it at load time) and BSS tails past each section's raw
        # data. Reads there return nothing, like IDA's 0xFF-filled bytes.
        uninit: List[Tuple[int, int]] = []
        iat: List[Tuple[int, int]] = []
        dd_base = opt + (112 if magic == 0x20B else 96)
        if dd_base + 13 * 8 <= len(data):
            iat_rva, iat_size = struct.unpack_from("<II", data, dd_base + 12 * 8)
            if iat_rva and iat_size:
                iat.append((image_base + iat_rva, image_base + iat_rva + iat_size))
                uninit.extend(iat)
        for section in sections:
            if section["vsize"] > section["size"]:
                uninit.append(
                    (
                        section["vaddr"] + section["size"],
                        section["vaddr"] + section["vsize"],
                    )
                )
    except (struct.error, IndexError):
        return None
    return PEInfo(image_base, sections, uninit, iat)


#: FuncInfo magics seen in the wild: __CxxFrameHandler3 (0x19930520/21) and
#: __CxxFrameHandler4 (0x19930522) handler data.
_FUNCINFO_MAGICS = {0x19930520, 0x19930521, 0x19930522}


def _read_cint(data: bytes, off: int) -> Tuple[int, int]:
    """Read an FH4 compressed integer; return ``(value, next_offset)``.

    The low bits of the first byte tag the length: ``0`` -> 1 byte,
    ``01`` -> 2, ``011`` -> 3, ``0111`` -> 4, otherwise 5; the value is the
    little-endian integer shifted right by the tag length.
    """
    first = data[off]
    if first & 1 == 0:
        return first >> 1, off + 1
    if first & 3 == 1:
        return struct.unpack_from("<H", data, off)[0] >> 2, off + 2
    if first & 7 == 3:
        raw = data[off] | (data[off + 1] << 8) | (data[off + 2] << 16)
        return raw >> 3, off + 3
    if first & 0xF == 7:
        return struct.unpack_from("<I", data, off)[0] >> 4, off + 4
    return int.from_bytes(data[off:off + 5], "little") >> 5, off + 5


def parse_eh_boundaries(
    path: str, pe: PEInfo
) -> Tuple[Dict[int, List[int]], List[int], List[int], Dict[int, List[int]]]:
    """Parse PE64 ``.pdata`` unwind metadata for EH block boundaries/funclets.

    For functions with a C++ exception handler, the unwind handler data is a
    ``FuncInfo``/``FuncInfo4`` structure whose IP-to-state map lists every
    address where the exception state changes.  IDA splits basic blocks at
    those addresses; radare2 ignores them, so they must be recovered here.
    Catch handlers, unwind actions and SEH scope handlers are funclets that
    IDA exports as their own functions, so their addresses are collected too.

    Returns ``({function_va: [boundary_va, ...]}, [funclet_va, ...],
    [catch_funclet_va, ...])``.
    """
    boundaries: Dict[int, List[int]] = {}
    funclets: List[int] = []
    catch_funclets: List[int] = []
    transitions: Dict[int, List[int]] = {}
    if not pe.sections:
        return boundaries, funclets, catch_funclets, transitions
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return boundaries, funclets, catch_funclets, transitions

    def rva2off(rva: int) -> Optional[int]:
        va = pe.image_base + rva
        for section in pe.sections:
            if section["vaddr"] <= va < section["vaddr"] + max(
                section["vsize"], section["size"]
            ):
                return section["paddr"] + (va - section["vaddr"])
        return None

    def exec_va(rva: int) -> Optional[int]:
        va = pe.image_base + rva
        for low, high in pe.exec_ranges:
            if low <= va < high:
                return va
        return None

    pdata = pe.section(".pdata")
    if pdata is None or not pdata["size"]:
        return boundaries, funclets
    poff = pdata["paddr"]
    base = pe.image_base
    count = pdata["size"] // 12
    for index in range(count):
        try:
            begin_rva, end_rva, unwind_rva = struct.unpack_from(
                "<III", data, poff + index * 12
            )
            uoff = rva2off(unwind_rva)
            if uoff is None or uoff + 4 > len(data):
                continue
            flags = data[uoff] & 0xF8
            if not flags & 0x18:
                continue  # no exception handler -> no state map
            codes = data[uoff + 2]
            # UNWIND_INFO: 4-byte header + 2-byte codes, DWORD aligned; the
            # handler RVA and handler-data RVA follow immediately.
            hoff = (uoff + 4 + 2 * codes + 3) & ~3
            if hoff + 8 > len(data):
                continue
            handler_rva, hdata = struct.unpack_from("<II", data, hoff)
            begin_va, end_va = base + begin_rva, base + end_rva
            points = []
            foff = rva2off(hdata)
            if (
                foff is not None
                and foff + 28 <= len(data)
                and struct.unpack_from("<I", data, foff)[0] in _FUNCINFO_MAGICS
            ):
                # __CxxFrameHandler3/4: handler data is an RVA to a FuncInfo
                # structure; every IP-to-state transition is a block boundary.
                fields = struct.unpack_from("<10i", data, foff)
                _magic, max_st, disp_uw, n_try, disp_try, n_ip, disp_ip = fields[:7]
                if 0 < n_ip <= 4096:
                    ip_off = rva2off(disp_ip)
                    if ip_off is not None and ip_off + n_ip * 8 <= len(data):
                        for j in range(n_ip):
                            ip, _state = struct.unpack_from("<2i", data, ip_off + j * 8)
                            va = base + ip
                            if begin_va < va < end_va:
                                points.append(va)
                # Unwind actions inside the function are destructor-call
                # sites (block boundaries); outside the function they are
                # standalone funclets IDA exports as functions.
                if 0 < max_st <= 4096:
                    uw_off = rva2off(disp_uw)
                    if uw_off is not None and uw_off + max_st * 8 <= len(data):
                        for j in range(max_st):
                            _to, act = struct.unpack_from("<iI", data, uw_off + j * 8)
                            va = exec_va(act)
                            if va is not None:
                                if begin_va < va < end_va:
                                    points.append(va)
                                else:
                                    funclets.append(va)
                # Try-block catch handler maps hold the catch$ funclet
                # addresses IDA exports as separate functions.
                if 0 < n_try <= 4096:
                    t_off = rva2off(disp_try)
                    if t_off is not None and t_off + n_try * 20 <= len(data):
                        for j in range(n_try):
                            _tl, _th, _ch, n_c, d_ch = struct.unpack_from(
                                "<iiiIi", data, t_off + j * 20
                            )
                            if not 0 < n_c <= 64:
                                continue
                            ch_off = rva2off(d_ch)
                            if ch_off is None or ch_off + n_c * 20 > len(data):
                                continue
                            for k in range(n_c):
                                _a, _dt, _dco, d_h, _df = struct.unpack_from(
                                    "<IiiIi", data, ch_off + k * 20
                                )
                                va = exec_va(d_h)
                                if va is not None:
                                    if begin_va < va < end_va:
                                        points.append(va)
                                    else:
                                        funclets.append(va)
                                        catch_funclets.append(va)
            else:
                # Other handler-data formats, tried in order:
                #  1. an inline SCOPE_TABLE (__C_specific_handler stores the
                #     record count in the handler-data dword itself; GS
                #     handler data prefixes it with a cookie offset), or
                #  2. a GS_HANDLER_DATA structure at the handler-data RVA
                #     (cookie dword, then an inline SCOPE_TABLE), or
                #  3. an FH4 FuncInfo4 record (__CxxFrameHandler4).
                records = None
                for count_off in (hoff + 4, hoff + 8, hoff + 12):
                    records = _scope_records(data, count_off, begin_rva, end_rva)
                    if records is not None:
                        break
                if records is None and foff is not None:
                    for add in (4, 8, 12):
                        records = _scope_records(
                            data, foff + add, begin_rva, end_rva
                        )
                        if records is not None:
                            break
                if records is not None:
                    for b2, e2, h2, jt in records:
                        for va in (base + b2, base + e2, base + jt):
                            if begin_va < va < end_va:
                                points.append(va)
                        for rva in (h2, jt):
                            va = exec_va(rva)
                            if va is not None:
                                if begin_va < va < end_va:
                                    points.append(va)
                                else:
                                    funclets.append(va)
                elif foff is not None:
                    trans: List[int] = []
                    points.extend(
                        _parse_fh4(
                            data, foff, begin_va, end_va, base,
                            rva2off, exec_va, funclets, catch_funclets, trans,
                        )
                    )
                    if trans:
                        transitions[begin_va] = trans
            if points:
                boundaries.setdefault(begin_va, [])
                boundaries[begin_va] = sorted(set(boundaries[begin_va] + points))
        except (struct.error, IndexError):
            continue
    return boundaries, funclets, catch_funclets, transitions


def _scope_records(
    data: bytes, count_off: int, begin_rva: int, end_rva: int
) -> Optional[List[Tuple[int, int, int, int]]]:
    """Return a validated ``SCOPE_TABLE`` or ``None``.

    ``__C_specific_handler`` records are {Begin, End, Handler, JumpTarget}
    dwords covering ranges inside the owning function; the strict range
    check rejects handler data that is actually a different structure.
    """
    if count_off < 0 or count_off + 4 > len(data):
        return None
    (count,) = struct.unpack_from("<I", data, count_off)
    if not 0 < count <= 256 or count_off + 4 + count * 16 > len(data):
        return None
    records = []
    for j in range(count):
        b2, e2, h2, jt = struct.unpack_from("<4I", data, count_off + 4 + j * 16)
        if not (begin_rva <= b2 < e2 <= end_rva):
            return None
        records.append((b2, e2, h2, jt))
    return records


def _parse_fh4(
    data: bytes,
    foff: int,
    begin_va: int,
    end_va: int,
    base: int,
    rva2off,
    exec_va,
    funclets: List[int],
    catch_funclets: List[int],
    trans: List[int],
) -> List[int]:
    """Parse an FH4 ``FuncInfo4`` record for ``__CxxFrameHandler4``.

    The byte at ``foff`` is a header bitfield: 0x01 isCatch, 0x02
    isSeparated, 0x04 BBT, 0x08 has unwind map, 0x10 has try-block map.
    Conditional compressed/RVA fields follow, then the IP-to-state map RVA.
    """
    points: List[int] = []
    header = data[foff]
    pos = foff + 1
    if header & 0x04:
        _bbt, pos = _read_cint(data, pos)
    disp_uw = disp_try = None
    if header & 0x08:
        disp_uw = struct.unpack_from("<I", data, pos)[0]
        pos += 4
    if header & 0x10:
        disp_try = struct.unpack_from("<I", data, pos)[0]
        pos += 4
    if pos + 4 > len(data):
        return points
    disp_ip = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if header & 0x01:
        catch_funclets.append(begin_va)

    def add_point(va: Optional[int]) -> None:
        if va is not None and begin_va < va < end_va:
            points.append(va)

    def add_funclet(va: Optional[int]) -> None:
        if va is None:
            return
        if begin_va < va < end_va:
            points.append(va)
        else:
            funclets.append(va)

    def ip_map(map_rva: int, map_base: int) -> None:
        ioff = rva2off(map_rva)
        if ioff is None:
            return
        count, p = _read_cint(data, ioff)
        ip = 0
        for _j in range(min(count, 4096)):
            delta, p = _read_cint(data, p)
            state, p = _read_cint(data, p)
            ip += delta
            # State transitions are only *candidate* boundaries, and only
            # for functions with a try-block map: try-region starts are
            # landing areas the EH dispatcher can reach, so IDA makes them
            # basic blocks.  For destructor-only functions (no try map)
            # the state changes are unwind bookkeeping and never split the
            # chart.  Stored states are biased by one, so 0 means the
            # invalid/-1 state (a scope exit) which never splits either.
            va = map_base + ip
            if begin_va < va < end_va and state >= 1 and disp_try is not None:
                trans.append(va)

    if header & 0x02:
        # isSeparated: dispIPtoStateMap points at a list of
        # {addrStartRVA, dispOfIPMap} pairs, one per code contribution.
        soff = rva2off(disp_ip)
        if soff is not None:
            count, p = _read_cint(data, soff)
            for _j in range(min(count, 64)):
                a_rva, m_rva = struct.unpack_from("<II", data, p)
                p += 8
                ip_map(m_rva, base + a_rva)
    else:
        ip_map(disp_ip, begin_va)

    if disp_uw is not None:
        uoff = rva2off(disp_uw)
        if uoff is not None:
            count, p = _read_cint(data, uoff)
            for _j in range(min(count, 4096)):
                packed, p = _read_cint(data, p)
                etype = packed & 3
                if etype == 0:
                    continue
                action = struct.unpack_from("<I", data, p)[0]
                p += 4
                if etype in (1, 2):
                    _obj, p = _read_cint(data, p)
                add_funclet(exec_va(action))
    if disp_try is not None:
        toff = rva2off(disp_try)
        if toff is not None:
            count, p = _read_cint(data, toff)
            for _j in range(min(count, 4096)):
                _tl, p = _read_cint(data, p)
                _th, p = _read_cint(data, p)
                _ch, p = _read_cint(data, p)
                harr = struct.unpack_from("<I", data, p)[0]
                p += 4
                aoff = rva2off(harr)
                if aoff is None:
                    continue
                ncatch, p = _read_cint(data, aoff)
                for _k in range(min(ncatch, 64)):
                    hhdr = data[p]
                    p += 1
                    if hhdr & 0x01:
                        _adj, p = _read_cint(data, p)
                    if hhdr & 0x02:
                        p += 4
                    if hhdr & 0x04:
                        _dco, p = _read_cint(data, p)
                    (d_h,) = struct.unpack_from("<I", data, p)
                    p += 4
                    d_va = exec_va(d_h)
                    if d_va is not None and begin_va < d_va < end_va:
                        points.append(d_va)
                    elif d_va is not None:
                        funclets.append(d_va)
                        catch_funclets.append(d_va)
                    ncont = (hhdr >> 4) & 3
                    for _c in range(min(ncont, 2)):
                        cont, p = _read_cint(data, p)
                        va = base + cont if hhdr & 0x08 else begin_va + cont
                        add_point(va)
    return points


def parse_pdata_ranges(
    pdata_bytes: bytes, image_base: int, exec_ranges: List[Tuple[int, int]]
) -> List[Tuple[int, int]]:
    """Return ``(begin, end)`` virtual addresses of each ``RUNTIME_FUNCTION``.

    ``.pdata`` is page aligned, so after the real entries there is a
    zero-filled tail; entries whose begin/end are zero, inverted or outside
    an executable section are padding or data and are skipped.
    """
    ranges: List[Tuple[int, int]] = []
    for offset in range(0, len(pdata_bytes) - 11, 12):
        begin, end, _unwind = struct.unpack_from("<III", pdata_bytes, offset)
        if begin == 0 or end == 0 or end <= begin:
            continue
        start = image_base + begin
        stop = image_base + end
        if not any(low <= start < high for low, high in exec_ranges):
            continue
        ranges.append((start, stop))
    return ranges


def parse_pdata_entries(
    pdata_bytes: bytes, image_base: int, exec_ranges: List[Tuple[int, int]]
) -> List[int]:
    """Return the function starts of a PE64 ``.pdata`` directory."""
    return [begin for begin, _end in parse_pdata_ranges(
        pdata_bytes, image_base, exec_ranges
    )]


def _capstone_engine(bits: int, big_endian: bool):
    global _CS_AVAILABLE
    if _CS_AVAILABLE is False:
        return None
    try:
        import capstone
    except ImportError:
        _CS_AVAILABLE = False
        return None
    _CS_AVAILABLE = True
    key = (bits, big_endian)
    if key not in _CS_ENGINES:
        mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
        if big_endian:
            mode |= capstone.CS_MODE_BIG_ENDIAN
        engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
        engine.detail = True
        _CS_ENGINES[key] = engine
    return _CS_ENGINES[key]


def capstone_operand_layout(code: bytes, bits: int = 64) -> Optional[List[dict]]:
    """Return IDA-style operand types and byte offsets for one x86 instruction.

    ``offb`` is the byte offset of the immediate/displacement field, which is
    what ``insn_t.ops[i].offb`` holds in IDA and what Diaphora subtracts from
    the instruction size to normalize the instruction bytes.
    """
    engine = _capstone_engine(bits, False)
    if engine is None:
        return None
    try:
        import capstone
    except ImportError:
        return None
    insn = next(engine.disasm(code, 0), None)
    if insn is None:
        return None
    encoding = insn.encoding
    rip = capstone.x86.X86_REG_RIP if bits == 64 else capstone.x86.X86_REG_EIP
    layout = []
    for operand in insn.operands:
        if operand.type == capstone.x86.X86_OP_REG:
            layout.append({"type": O_REG, "offb": 0})
        elif operand.type == capstone.x86.X86_OP_IMM:
            layout.append({"type": O_IMM, "offb": encoding.imm_offset if encoding.imm_size else 0})
        elif operand.type == capstone.x86.X86_OP_MEM:
            memory = operand.mem
            if memory.base == rip or (memory.base == 0 and memory.index == 0):
                kind = O_MEM
            elif encoding.disp_size:
                kind = O_DISPL
            else:
                kind = O_PHRASE
            offb = encoding.disp_offset if (kind != O_PHRASE and encoding.disp_size) else 0
            layout.append({"type": kind, "offb": offb})
        else:
            layout.append({"type": O_VOID, "offb": 0})
    return layout


def _split_sections(text: str) -> Dict[str, str]:
    pattern = re.compile(r"(?m)^" + re.escape(SECTION_PREFIX) + r"(\S+)\s*$")
    sections: Dict[str, str] = {}
    matches = list(pattern.finditer(text))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections.setdefault(match.group(1), text[start:end])
    return sections


def _parse_json(value: Optional[str]) -> Any:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return json.loads(value)


def _parse_json_stream(value: Optional[str]) -> List[Any]:
    if not value:
        return []
    decoder = json.JSONDecoder()
    position = 0
    length = len(value)
    results = []
    while position < length:
        while position < length and value[position] in " \t\r\n":
            position += 1
        if position >= length:
            break
        obj, position = decoder.raw_decode(value, position)
        results.append(obj)
    return results


class R2BinaryCache:
    """In-memory snapshot of everything radare2 knows about one binary."""

    def __init__(
        self,
        input_path: str,
        load_pdb: bool = False,
        ident_libs: bool = True,
        decompiler_cmd: str = "pdg",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        timeout: int = 3600,
    ):
        self.input_path = os.path.abspath(input_path)
        if not os.path.isfile(self.input_path):
            raise FileNotFoundError(self.input_path)

        self.r2_bin = find_r2_binary()
        if self.r2_bin is None:
            raise RuntimeError(
                "radare2 not found; install it and/or add its bin directory to PATH"
            )

        self.load_pdb = load_pdb
        self.ident_libs = ident_libs
        self.decompiler_cmd = decompiler_cmd
        self.chunk_size = max(1, chunk_size)
        self.timeout = max(1, int(timeout))
        self.cmd_count = 0

        self.pe = parse_pe(self.input_path)
        (
            self.eh_boundaries,
            self.eh_funclets,
            self.eh_catch,
            self.eh_transitions,
        ) = (
            parse_eh_boundaries(self.input_path, self.pe)
            if self.pe
            else ({}, [], [], {})
        )
        self.synthesized: set = set()
        self.insn_owned: set = set()
        self._orphan_pieces: List[dict] = []
        self.image_base = self.pe.image_base if self.pe else 0
        self.bits = 64 if self.image_base > 0xFFFFFFFF else 32
        self.arch = "x86"
        self.idp_name = "pc"
        self.min_ea = 0
        self.max_ea = 0
        self.md5sum = self._file_md5()

        self.functions: Dict[int, dict] = {}
        self.sorted_func_eas: List[int] = []
        self.func_blocks: Dict[int, List[dict]] = {}
        self.insns: Dict[int, dict] = {}
        self.names: Dict[int, Tuple[str, str, Optional[str]]] = {}
        self.strings_by_ea: Dict[int, dict] = {}
        self.comments_by_ea: Dict[int, str] = {}
        self.code_refs_from: Dict[int, List[int]] = {}
        self.code_refs_to: Dict[int, List[int]] = {}
        self.data_refs_from: Dict[int, List[int]] = {}
        self.data_refs_to: Dict[int, List[int]] = {}
        self.try_regions: Dict[int, Dict[int, Dict[str, int]]] = {}
        self.switches_by_insn: Dict[int, Tuple[int, List[int]]] = {}
        self.segments: List[dict] = []
        self.sorted_insn_eas: List[int] = []
        self.insn_ends: Dict[int, int] = {}

        self._segments_bytes: List[Tuple[int, bytes]] = []
        self._pe_section_bytes: Dict[str, bytes] = {}
        self._func_starts: List[int] = []
        self.decompiled: Dict[int, dict] = {}
        self.decompiler_available: Optional[bool] = None
        self._closed = False
        self._pdata_range_cache: Optional[List[Tuple[int, int]]] = None

        self._build()

    # -- public API ---------------------------------------------------------

    def close(self) -> None:
        self._closed = True
        self._segments_bytes = []
        self._pe_section_bytes = {}
        self.insns = {}
        self.insn_ends = {}

    def ensure_function_cached(self, func_ea: int) -> dict:
        func = self.functions.get(func_ea)
        if func is None:
            raise KeyError("Unknown function at 0x%x" % func_ea)
        return func

    def get_insn(self, ea: int) -> Optional[dict]:
        return self.insns.get(ea)

    def get_blocks(self, func_ea: int) -> List[dict]:
        return self.func_blocks.get(func_ea, [])

    def is_mapped(self, ea: int) -> bool:
        return self.get_segment_for(ea) is not None

    def _pe_bytes(self, ea: int, size: int) -> bytes:
        if self.pe is None or not self._pe_section_bytes:
            return b""
        for start, end in self.pe.uninit_ranges:
            if ea < end and ea + size > start:
                return b""
        section = self.get_segment_for(ea)
        if section is None:
            return b""
        raw = self._pe_section_bytes.get(section["name"])
        if raw is None:
            return b""
        offset = ea - section["vaddr"]
        if offset < 0:
            return b""
        chunk = raw[offset : offset + size]
        if len(chunk) < size:
            chunk += b"\x00" * (size - len(chunk))
        return chunk

    def get_bytes(self, ea: int, size: int) -> bytes:
        if size <= 0:
            return b""
        if self.pe is not None:
            data = self._pe_bytes(ea, size)
            if len(data) == size:
                return data
            return b""
        for start, data in self._segments_bytes:
            if start <= ea and ea + size <= start + len(data):
                offset = ea - start
                return data[offset : offset + size]
        insn = self.insns.get(ea)
        if insn is not None:
            raw = insn.get("raw_bytes") or b""
            if len(raw) >= size:
                return raw[:size]
        return b""

    def get_name(self, ea: int) -> str:
        entry = self.names.get(ea)
        if entry is None:
            return ""
        return entry[0]

    def get_true_name(self, ea: int) -> str:
        entry = self.names.get(ea)
        if entry is None:
            return ""
        return entry[1]

    def get_func_ea(self, ea: int) -> int:
        """Return the function containing ``ea`` or ``BADADDR``."""
        index = 0
        low, high = 0, len(self._func_starts) - 1
        while low <= high:
            middle = (low + high) // 2
            if self._func_starts[middle] <= ea:
                index = middle
                low = middle + 1
            else:
                high = middle - 1
        candidate = self._func_starts[index] if self._func_starts else None
        while candidate is not None:
            func = self.functions[candidate]
            if candidate <= ea < candidate + max(func["size"], 1):
                return candidate
            break
        return 0xFFFFFFFFFFFFFFFF

    def get_code_refs_from(self, ea: int, flow: int = 0) -> List[int]:
        refs = list(self.code_refs_from.get(ea, []))
        # Only block-owned heads produce flow xrefs: stray decoded bytes in
        # unowned padding (e.g. the ``nop`` before a function start) are not
        # heads in IDA and carry no ``fl_F``.
        if flow and ea in self.insn_owned:
            successor = _flow_successor(self.insns.get(ea))
            if successor is not None and successor not in refs:
                refs.append(successor)
        return refs

    def get_code_refs_to(self, ea: int, flow: int = 0) -> List[int]:
        refs = list(self.code_refs_to.get(ea, []))
        if flow:
            predecessor_ea = self.insn_ends.get(ea)
            if (
                predecessor_ea is not None
                and predecessor_ea in self.insn_owned
                and predecessor_ea not in refs
            ):
                predecessor = self.insns.get(predecessor_ea)
                if _flow_successor(predecessor) == ea:
                    refs.append(predecessor_ea)
        return refs

    def get_data_refs_from(self, ea: int) -> List[int]:
        # radare2's ``axtj`` reports pseudo-references like ``lea ecx,
        # [rcx*2 + 1] -> 1`` that are not memory operands; IDA only creates
        # data xrefs to mapped addresses.
        return [
            target
            for target in self.data_refs_from.get(ea, [])
            if self.is_mapped(target)
        ]

    def get_segment_for(self, ea: int) -> Optional[dict]:
        for segment in self.segments:
            if segment["vaddr"] <= ea < segment["vaddr"] + segment["vsize"]:
                return segment
        return None

    def instruction_heads(self, start: int, end: int) -> List[int]:
        heads = []
        ea = start
        while ea < end:
            insn = self.insns.get(ea)
            if insn is None:
                break
            heads.append(ea)
            ea += max(insn["size"], 1)
        return heads

    def prune_functions(self, predicate) -> None:
        """Drop functions for which ``predicate(info)`` is false.

        Used by the CLI's ``-nbbs`` / ``-a`` filters: everything downstream
        (``Functions()``, decompilation batches, export) then sees only the
        selected functions.
        """
        keep = {
            ea: info for ea, info in self.functions.items() if predicate(info)
        }
        removed = set(self.functions) - set(keep)
        self.functions = keep
        self.sorted_func_eas = sorted(keep)
        self._func_starts = list(self.sorted_func_eas)
        for ea in removed:
            self.func_blocks.pop(ea, None)
            self.decompiled.pop(ea, None)
            self.names.pop(ea, None)

    # -- decompiler ---------------------------------------------------------

    def decompile_all(self, func_eas: Optional[List[int]] = None) -> None:
        """Decompile every function in one radare2 run and cache the result."""
        if self.decompiler_available is False:
            return
        targets = list(func_eas if func_eas is not None else self.sorted_func_eas)
        script = self._analysis_prefix()
        for func_ea in targets:
            script.append("?e " + SECTION_PREFIX + "c:%x" % func_ea)
            script.append("pdg @ 0x%x" % func_ea)
            script.append("?e " + SECTION_PREFIX + "x:%x" % func_ea)
            script.append("pdgx @ 0x%x" % func_ea)
        raw = self._run_script(script)
        data = _split_sections(raw)

        if all(
            "You need to install the plugin" in (data.get("c:%x" % ea) or "")
            for ea in targets
        ):
            self.decompiler_available = False
            return
        self.decompiler_available = True

        for func_ea in targets:
            text = data.get("c:%x" % func_ea) or ""
            xml = data.get("x:%x" % func_ea) or ""
            self.decompiled[func_ea] = _build_decompilation(text, xml)

    def get_decompiled(self, func_ea: int) -> Optional[dict]:
        if func_ea in self.decompiled:
            return self.decompiled[func_ea]
        if self.decompiler_available is False:
            return None
        self.decompile_all([func_ea])
        return self.decompiled.get(func_ea)

    # -- loading ------------------------------------------------------------

    def _file_md5(self) -> str:
        digest = hashlib.md5()
        with open(self.input_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _pdata_ranges(self) -> List[Tuple[int, int]]:
        if self._pdata_range_cache is None:
            self._pdata_range_cache = []
            if self.pe is not None and self.bits == 64:
                raw = self.pe.read_section(self.input_path, ".pdata")
                if raw:
                    self._pdata_range_cache = parse_pdata_ranges(
                        raw, self.pe.image_base, self.pe.exec_ranges
                    )
        return self._pdata_range_cache

    def _pdata_seeds(self) -> List[int]:
        return [begin for begin, _end in self._pdata_ranges()]

    def _run_script(self, script: List[str]) -> str:
        handle, script_path = tempfile.mkstemp(suffix=".r2", prefix="r2diaphora_")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write("\n".join(script) + "\n")
            command = [
                self.r2_bin,
                "-q",
                "-e",
                "scr.color=0",
                "-e",
                "bin.relocs.apply=true",
                "-i",
                script_path,
                self.input_path,
            ]
            self.cmd_count += 1
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
            )
            return completed.stdout.decode("utf-8", "replace")
        finally:
            try:
                os.remove(script_path)
            except OSError:
                pass

    def _analysis_prefix(self) -> List[str]:
        script = [
            "e log.level=0",
            "e scr.color=0",
            "e asm.flags=false",
            "e asm.bytes=false",
            "e asm.comments=false",
            "e io.cache=true",
        ]
        if self.load_pdb:
            script.extend(["idpd", "idp", "af @@ pdb.*"])
        for seed in self._pdata_seeds():
            script.append("af @ 0x%x" % seed)
        script.append("aaaa")
        return script

    def _build(self) -> None:
        script = self._analysis_prefix()

        sections: List[Tuple[str, str]] = [
            ("info", "ij"),
            ("sections", "iSj"),
            ("functions", "aflj"),
            ("imports", "isj"),
            ("strings", "izj"),
            ("comments", "CCj"),
            ("flags", "fj"),
            ("blocks", "afbj @@f"),
            ("callgraph", "afxj @@f"),
        ]
        if self.pe is not None:
            self._load_pe_section_bytes()

        for name, command in sections:
            script.append("?e " + SECTION_PREFIX + name)
            script.append(command)

        raw = self._run_script(script)
        data = _split_sections(raw)

        self._parse_info(_parse_json(data.get("info")))
        self._parse_sections(_parse_json(data.get("sections")))
        self._parse_functions(_parse_json(data.get("functions")))
        self._parse_blocks(_parse_json_stream(data.get("blocks")))
        self._parse_imports(_parse_json(data.get("imports")))
        self._parse_strings(_parse_json(data.get("strings")))
        self._parse_comments(_parse_json(data.get("comments")))
        self._parse_flags(_parse_json(data.get("flags")))
        self._parse_callgraph(_parse_json_stream(data.get("callgraph")))
        if self.pe is None:
            self._load_r2_memory()

        self._load_instructions()
        self.sorted_insn_eas = sorted(self.insns)

    def _load_pe_section_bytes(self) -> None:
        """Read the raw file-backed bytes of every mapped PE section.

        ``get_bytes`` is on the hot path of the exporter (once per instruction),
        so serving it from a small in-memory copy of the image is both faster
        and more accurate than asking radare2 for hex dumps.
        """
        try:
            with open(self.input_path, "rb") as handle:
                for section in self.pe.sections:
                    if section["size"] == 0:
                        continue
                    handle.seek(section["paddr"])
                    self._pe_section_bytes[section["name"]] = handle.read(section["size"])
        except OSError:
            self._pe_section_bytes = {}

    def _load_r2_memory(self) -> None:
        script = ["e log.level=0"]
        targets = []
        for index, segment in enumerate(self.segments):
            if "x" not in segment.get("perm", ""):
                continue
            if segment["vsize"] == 0:
                continue
            targets.append((index, segment))
            script.append("?e " + SECTION_PREFIX + "memory%d" % index)
            script.append("p8 %d @ 0x%x" % (segment["vsize"], segment["vaddr"]))
        if not targets:
            return
        raw = self._run_script(script)
        data = _split_sections(raw)
        for index, segment in targets:
            payload = (data.get("memory%d" % index) or "").strip()
            if not payload:
                continue
            try:
                self._segments_bytes.append((segment["vaddr"], bytes.fromhex(payload)))
            except ValueError:
                continue

    def _parse_info(self, info: Optional[dict]) -> None:
        if not info:
            return
        binary = info.get("bin") or {}
        self.bits = int(binary.get("bits") or self.bits)
        arch = (binary.get("arch") or "x86").lower()
        self.arch = arch
        if binary.get("baddr") is not None:
            self.image_base = int(binary["baddr"])
        if arch in ("x86", "x86_64", "amd64", "i386"):
            # IDA 9.x reports "pc" (-> "pc64"); <=8.x reported "metapc".
            self.idp_name = "pc"
        elif arch.startswith("arm"):
            self.idp_name = "arm"
        else:
            self.idp_name = arch

    def _parse_sections(self, sections: Optional[List[dict]]) -> None:
        self.segments = []
        low = None
        high = None
        for section in sections or []:
            segment = {
                "name": section.get("name", ""),
                "vaddr": int(section.get("vaddr", 0)),
                "vsize": int(section.get("vsize") or section.get("size") or 0),
                "perm": section.get("perm", ""),
            }
            self.segments.append(segment)
            start = segment["vaddr"]
            end = start + segment["vsize"]
            low = start if low is None else min(low, start)
            high = end if high is None else max(high, end)
        if low is not None:
            self.min_ea, self.max_ea = low, high
        elif self.pe is not None:
            self.min_ea = self.image_base
            self.max_ea = self.image_base

    def _parse_functions(self, functions: Optional[List[dict]]) -> None:
        self.functions = {}
        for entry in functions or []:
            ea = int(entry["addr"])
            self.functions[ea] = {
                "addr": ea,
                "name": _normalize_name(entry.get("name", "")),
                "r2_name": entry.get("name", ""),
                "size": int(entry.get("size") or entry.get("realsz") or 0),
                "ninstrs": int(entry.get("ninstrs") or 0),
                "nbbs": int(entry.get("nbbs") or 0),
                "edges": int(entry.get("edges") or 0),
                "indegree": int(entry.get("indegree") or 0),
                "outdegree": int(entry.get("outdegree") or 0),
                "cc": int(entry.get("cc") or 0),
                "flags": entry.get("type", ""),
                "nargs": int(entry.get("nargs") or 0),
                "nlocals": int(entry.get("nlocals") or 0),
                "calltype": entry.get("calltype", ""),
                "stackframe": int(entry.get("stackframe") or 0),
            }
        self.sorted_func_eas = sorted(self.functions)
        self._func_starts = list(self.sorted_func_eas)

    def _parse_blocks(self, blocks_stream: List[Any]) -> None:
        self.func_blocks = {}
        for entry in blocks_stream:
            if not entry:
                continue
            for block in entry:
                block_addr = int(block.get("addr", 0))
                func_ea = self._function_for_address(block_addr)
                if func_ea is None:
                    continue
                blocks = self.func_blocks.setdefault(func_ea, [])
                blocks.append(
                    {
                        "addr": block_addr,
                        "size": int(block.get("size") or 0),
                        "jump": _int_or_none(block.get("jump")),
                        "fail": _int_or_none(block.get("fail")),
                        "ninstr": int(block.get("ninstr") or 0),
                        "instrs": [int(x) for x in (block.get("instrs") or [])],
                    }
                )
        for func_ea, blocks in self.func_blocks.items():
            blocks.sort(key=lambda block: block["addr"])
            self.func_blocks[func_ea] = blocks
            if func_ea in self.functions and not self.functions[func_ea]["nbbs"]:
                self.functions[func_ea]["nbbs"] = len(blocks)

    def _function_for_address(self, address: int) -> Optional[int]:
        import bisect

        index = bisect.bisect_right(self._func_starts, address) - 1
        if index < 0:
            return None
        candidate = self._func_starts[index]
        span = max(self.functions[candidate]["size"], 1)
        if candidate <= address < candidate + span:
            return candidate
        return None

    def _parse_imports(self, imports: Optional[List[dict]]) -> None:
        for entry in imports or []:
            name = entry.get("name") or ""
            if name.startswith("imp."):
                name = name[4:]
            address = entry.get("plt") or entry.get("got") or 0
            try:
                address = int(address)
            except (TypeError, ValueError):
                continue
            if address:
                self.names.setdefault(address, (name, name, None))

    def _parse_strings(self, strings: Optional[List[dict]]) -> None:
        self.strings_by_ea = {}
        for entry in strings or []:
            address = int(entry.get("vaddr") or 0)
            if not address:
                continue
            self.strings_by_ea[address] = {
                "ea": address,
                "string": entry.get("string", ""),
                "length": int(entry.get("length") or entry.get("size") or 0),
                "type": entry.get("type", "ascii"),
            }

    def _parse_comments(self, comments: Optional[List[dict]]) -> None:
        self.comments_by_ea = {}
        for entry in comments or []:
            address = int(entry.get("offset") or 0)
            if not address:
                continue
            self.comments_by_ea[address] = entry.get("name", "")

    def _parse_flags(self, flags: Optional[List[dict]]) -> None:
        try_re = re.compile(r"^try\.(\d+)\.([0-9a-fA-F]+)\.(\w+)$")
        for entry in flags or []:
            address = entry.get("offset")
            if address is None:
                address = entry.get("addr")
            try:
                address = int(address or 0)
            except (TypeError, ValueError):
                continue
            if not address:
                continue
            name = entry.get("name") or ""
            if not name:
                continue
            # ``try.N.<func>.{from,to,filter,catch}`` flags carry the structured
            # exception-handling ranges radare2 recovered from PE .pdata.  IDA
            # models these as basic-block boundaries plus an edge to the filter
            # funclet, so keep them for FlowChart instead of using them as names.
            match = try_re.match(name)
            if match is not None:
                region_index = int(match.group(1))
                func_ea = int(match.group(2), 16)
                regions = self.try_regions.setdefault(func_ea, {})
                regions.setdefault(region_index, {})[match.group(3)] = address
                continue
            normalized = _normalize_name(name)
            if not normalized:
                continue
            existing = self.names.get(address)
            if existing is not None and not existing[0].startswith("sub_"):
                continue
            self.names[address] = (normalized, name, None)

    def _is_executable(self, ea: int) -> bool:
        segment = self.get_segment_for(ea)
        return segment is not None and "x" in segment.get("perm", "")

    def _parse_callgraph(self, callgraph_stream: List[Any]) -> None:
        for entry in callgraph_stream:
            for edge in entry or []:
                source = _int_or_none(edge.get("from"))
                target = _int_or_none(edge.get("to"))
                if source is None or target is None:
                    continue
                # IDA xref semantics: a CALL is a code reference even when it
                # points at an import pointer (IDA resolves the callee), while
                # JMP/CODE edges landing on data (e.g. an indirect jump through
                # an import slot) are data references, not code.
                edge_type = edge.get("type")
                is_code = edge_type == "CALL" or (
                    edge_type in ("CODE", "JMP", "UJMP", "CJMP")
                    and self._is_executable(target)
                )
                if is_code:
                    refs = self.code_refs_from.setdefault(source, [])
                    if target not in refs:
                        refs.append(target)
                    back = self.code_refs_to.setdefault(target, [])
                    if source not in back:
                        back.append(source)
                else:
                    data = self.data_refs_from.setdefault(source, [])
                    if target not in data:
                        data.append(target)
                    back = self.data_refs_to.setdefault(target, [])
                    if source not in back:
                        back.append(source)

    def _parse_memory(self, name: str, payload: str) -> None:
        payload = payload.strip()
        if not payload:
            return
        try:
            raw = bytes.fromhex(payload)
        except ValueError:
            return
        start = None
        for segment in self.segments:
            if segment["name"] and ("memory%s" % self.segments.index(segment)) == name:
                start = segment["vaddr"]
                break
        if start is None:
            return
        self._segments_bytes.append((start, raw))

    def _load_instructions(self) -> None:
        pending = [ea for ea in self.sorted_func_eas if ea not in self.func_blocks]
        for ea in self.sorted_func_eas:
            if ea in self.func_blocks:
                continue
            block_end = ea + self.functions[ea]["size"]
            self.func_blocks[ea] = [
                {
                    "addr": ea,
                    "size": block_end - ea,
                    "jump": None,
                    "fail": None,
                    "ninstr": self.functions[ea]["ninstrs"],
                    "instrs": [],
                }
            ]
        del pending

        for start in range(0, len(self.sorted_func_eas), self.chunk_size):
            chunk = self.sorted_func_eas[start : start + self.chunk_size]
            script = ["e log.level=0"]
            for func_ea in chunk:
                count = self.functions[func_ea]["ninstrs"]
                if not count:
                    count = max(1, self.functions[func_ea]["size"] // 4)
                script.append("?e " + SECTION_PREFIX + "f:%x" % func_ea)
                script.append("s 0x%x" % func_ea)
                script.append("aoj %d" % count)
            raw = self._run_script(script)
            data = _split_sections(raw)
            for func_ea in chunk:
                for document in _parse_json_stream(data.get("f:%x" % func_ea)):
                    if not isinstance(document, list):
                        continue
                    for instruction in document:
                        self._register_instruction(instruction)

        for func_ea, blocks in self.func_blocks.items():
            for block in blocks:
                if not block["instrs"]:
                    block["instrs"] = self.instruction_heads(
                        block["addr"], block["addr"] + max(block["size"], 1)
                    )

        # The ``aoj <ninstrs>`` sweep decodes instructions linearly from the
        # function start, so padding bytes inside the range (e.g. an ``int3``
        # between two blocks) can consume slots and leave real instructions at
        # the tail undecoded.  agfj's per-block ``instrs`` are authoritative:
        # fill any gaps with single-instruction decodes.
        missing = sorted(
            {
                head
                for block in self.func_blocks.values()
                for sub in block
                for head in sub["instrs"]
            }
            - self.insns.keys()
        )
        for start in range(0, len(missing), self.chunk_size):
            batch = missing[start : start + self.chunk_size]
            script = ["e log.level=0"]
            for head in batch:
                script.append("s 0x%x" % head)
                script.append("aoj 1")
            raw = self._run_script(script)
            try:
                documents = _parse_json_stream(raw)
            except json.JSONDecodeError:
                documents = []
            for document in documents:
                if not isinstance(document, list):
                    continue
                for instruction in document:
                    self._register_instruction(instruction)

        self._synthesize_funclets()
        self._split_unowned()
        self._recover_gap_blocks()
        self.insn_owned = {
            head
            for blocks in self.func_blocks.values()
            for block in blocks
            for head in block.get("instrs", ())
        }
        self._register_insn_refs()

    def _register_insn_refs(self) -> None:
        """Create code/data xrefs from every decoded instruction operand.

        ``axtj`` only covers functions radare2 analyzed; synthesized
        funclets and gap-recovered code carry call/jump instructions IDA
        turns into xrefs as well (this is how destructor ``indegree`` picks
        up the calls inside EH dtor funclets).
        """
        for ea, insn in self.insns.items():
            itype = insn.get("type") or ""
            if itype in ("call", "ucall", "icall", "rcall", "ircall"):
                target = _int_or_none(insn.get("jump")) or _int_or_none(
                    insn.get("ptr")
                )
                if target is not None:
                    refs = self.code_refs_from.setdefault(ea, [])
                    if target not in refs:
                        refs.append(target)
                    back = self.code_refs_to.setdefault(target, [])
                    if ea not in back:
                        back.append(ea)
            elif itype in ("jmp", "cjmp", "ujmp", "ijmp", "rjmp", "irjmp"):
                target = _int_or_none(insn.get("jump")) or _int_or_none(
                    insn.get("ptr")
                )
                if target is None:
                    continue
                if self._is_executable(target):
                    refs = self.code_refs_from.setdefault(ea, [])
                    if target not in refs:
                        refs.append(target)
                    back = self.code_refs_to.setdefault(target, [])
                    if ea not in back:
                        back.append(ea)
                else:
                    refs = self.data_refs_from.setdefault(ea, [])
                    if target not in refs:
                        refs.append(target)
                    back = self.data_refs_to.setdefault(target, [])
                    if ea not in back:
                        back.append(ea)
        self._register_continuation_refs()

    def _register_continuation_refs(self) -> None:
        """MSVC funclet epilogues do ``lea reg, [target]; ret`` to resume the
        parent function.  IDA resolves the loaded address as the jump target
        and records a code xref at the ``ret``; radare2 only sees a data
        reference on the ``lea``.  Recreate the code xref so ``outdegree``
        and the callee's ``indegree`` match IDA's view.
        """
        # The load and the ``ret`` sit in one straight-line block but are not
        # adjacent (``lea rax, [x]; add rsp, N; pop rbp; ret``), so scan back
        # through the epilogue instructions of each ``ret``-ending block.
        for blocks in self.func_blocks.values():
            for block in blocks:
                instrs = block.get("instrs") or ()
                if not instrs:
                    continue
                tail = self.insns.get(instrs[-1]) or {}
                if (tail.get("type") or "") != "ret":
                    continue
                for head in reversed(instrs[:-1]):
                    prev = self.insns.get(head) or {}
                    itype = prev.get("type") or ""
                    if itype in ("mov", "lea"):
                        target = self._operand_code_va(prev)
                        if target is not None:
                            ea = int(instrs[-1])
                            refs = self.code_refs_from.setdefault(ea, [])
                            if target not in refs:
                                refs.append(target)
                            back = self.code_refs_to.setdefault(target, [])
                            if ea not in back:
                                back.append(ea)
                        break
                    if itype in _TERMINAL_TYPES or itype in _CALL_TYPES:
                        break

    def _operand_code_va(self, insn: dict) -> Optional[int]:
        """Immediate/mem operand of ``insn`` that points at executable code."""
        for op in insn.get("ops") or ():
            value = _int_or_none(op.get("value"))
            if value is not None and self._is_executable(value):
                return value
        return None

    def _synthesize_funclets(self) -> None:
        """Create function records for ``.pdata`` ranges radare2 never made.

        radare2 folds SEH funclets (``catch$N``/``dtor$N``) into the parent
        function's span: they are absent from ``aflj`` and their blocks from
        ``afbj``, so ``af @ <funclet>`` also no-ops inside the parent.  IDA
        exports every funclet as its own function.  For each .pdata range
        that does not already start a function, decode the instructions and
        rebuild a basic-block view directly.
        """
        orphans = [
            (begin, end)
            for begin, end in self._pdata_ranges()
            if begin not in self.functions
        ]
        # EH metadata names funclets that never get a .pdata entry of their
        # own (dtor$/catch$ helpers); infer their end from the next known
        # code boundary.  An address already inside another function's
        # blocks is ordinary code, not a funclet.
        covered: List[Tuple[int, int]] = []
        for blocks in self.func_blocks.values():
            for block in blocks:
                covered.append(
                    (block["addr"], block["addr"] + max(block["size"], 1))
                )
        covered.sort()
        covered_starts = [span[0] for span in covered]

        def block_covered(address: int) -> bool:
            index = bisect.bisect_right(covered_starts, address) - 1
            return (
                index >= 0
                and covered[index][0] <= address < covered[index][1]
            )

        bounds = sorted(
            set(self.functions) | {b for b, _ in self._pdata_ranges()}
            | set(self.eh_funclets)
        )
        for va in sorted(set(self.eh_funclets)):
            if va in self.functions or block_covered(va):
                continue
            stop = min((b for b in bounds if b > va), default=va + 0x400)
            orphans.append((va, min(stop, va + 0x400)))
        if not orphans:
            return
        # MSVC emits adjacent funclets whose .pdata ranges overlap; a funclet
        # effectively ends where the next nested entry begins.
        starts = sorted(self._pdata_ranges())
        trimmed = []
        for begin, end in orphans:
            stop = next((b for b, _ in starts if begin < b < end), end)
            trimmed.append((begin, min(stop, end)))
        orphans = trimmed
        script = ["e log.level=0"]
        for begin, end in orphans:
            script.append("?e " + SECTION_PREFIX + "u:%x" % begin)
            script.append("s 0x%x" % begin)
            script.append("aoj %d" % max(1, end - begin))
        raw = self._run_script(script)
        data = _split_sections(raw)
        for begin, end in orphans:
            decoded = []
            for document in _parse_json_stream(data.get("u:%x" % begin) or ""):
                if isinstance(document, list):
                    decoded.extend(document)
            insns = [
                insn for insn in decoded
                if begin <= int(insn.get("addr") or 0) < end
            ]
            insns.sort(key=lambda insn: insn["addr"])
            while insns and _is_padding_insn(insns[-1]):
                insns.pop()
            if not insns:
                continue
            for insn in insns:
                self._register_instruction(insn)
            self._add_funclet(begin, end, insns)

        if any(begin in self.functions for begin, _ in orphans):
            self.sorted_func_eas = sorted(self.functions)
            self._func_starts = list(self.sorted_func_eas)

    def _add_funclet(self, begin: int, end: int, insns: List[dict]) -> None:
        """Register a synthetic function at ``begin`` built from ``insns``.

        Blocks are reconstructed the way IDA's analyzer does it: a new block
        starts at every in-range branch target and after every instruction
        that does not fall through.
        """
        by_addr = {int(insn["addr"]): insn for insn in insns}
        end = int(insns[-1]["addr"]) + int(insns[-1].get("size") or 1)
        splits = {begin}
        for insn in insns:
            head = int(insn["addr"])
            jump = _int_or_none(insn.get("jump"))
            if jump is not None and begin <= jump < end and jump in by_addr:
                splits.add(jump)
            nxt = head + int(insn.get("size") or 0)
            itype = insn.get("type") or ""
            if itype in _STOP_FLOW_TYPES or itype == "cjmp":
                if begin < nxt < end and nxt in by_addr:
                    splits.add(nxt)
        points = sorted(splits)
        blocks = []
        for index, start in enumerate(points):
            stop = points[index + 1] if index + 1 < len(points) else end
            members = sorted(a for a in by_addr if start <= a < stop)
            last = by_addr[members[-1]] if members else None
            jump = fail = None
            if last is not None:
                last_t = last.get("type") or ""
                if last_t in ("jmp", "cjmp"):
                    jump = _int_or_none(last.get("jump"))
                if last_t not in _STOP_FLOW_TYPES:
                    fail = _flow_successor(last)
            blocks.append(
                {
                    "addr": start,
                    "size": stop - start,
                    "jump": jump,
                    "fail": fail,
                    "ninstr": len(members),
                    "instrs": members,
                }
            )
        # Only pieces reachable from the entry belong to this funclet; the
        # rest are adjacent thunks/funclets IDA exports as separate
        # functions.  They become gap-split candidates below.
        piece_starts = [block["addr"] for block in blocks]

        def piece_for(target: int) -> Optional[int]:
            index = bisect.bisect_right(piece_starts, target) - 1
            if index < 0:
                return None
            block = blocks[index]
            if block["addr"] <= target < block["addr"] + block["size"]:
                return index
            return None

        reachable = {0}
        work = [0]
        while work:
            index = work.pop()
            block = blocks[index]
            for target in (block.get("jump"), block.get("fail")):
                if target is None:
                    continue
                found = piece_for(int(target))
                if found is not None and found not in reachable:
                    reachable.add(found)
                    work.append(found)
        for index, block in enumerate(blocks):
            if index not in reachable:
                self._orphan_pieces.append(block)
        blocks = [b for i, b in enumerate(blocks) if i in reachable]
        self.synthesized.add(begin)
        self.functions[begin] = {
            "addr": begin,
            "name": "sub_%x" % begin,
            "r2_name": "",
            "size": end - begin,
            "ninstrs": len(insns),
            "nbbs": len(blocks),
            "edges": 0,
            "indegree": 0,
            "outdegree": 0,
            "cc": 0,
            "flags": "",
            "nargs": 0,
            "nlocals": 0,
            "calltype": "",
            "stackframe": 0,
        }
        self.func_blocks[begin] = blocks

    def _split_unowned(self) -> None:
        """Turn unowned executable code into functions.

        MSVC scatters tiny leaf helpers (destructor/atexit thunks, vtable
        methods, CRT initializers) between functions; radare2 merges them
        into neighbors or skips them, while IDA exports each as its own
        function.  Two sources: orphaned pieces left over when a
        synthesized funclet's range swallowed a neighbor, and gaps between
        covered code holding a terminal-ending instruction run.
        """
        for block in list(self._orphan_pieces):
            members = [
                self.insns[head]
                for head in block["instrs"]
                if head in self.insns
            ]
            members = [insn for insn in members if not _is_padding_insn(insn)]
            if not members:
                continue
            if (members[-1].get("type") or "") not in _TERMINAL_TYPES:
                continue
            self._add_funclet(
                block["addr"], block["addr"] + block["size"], members
            )

        covered = [
            (block["addr"], block["addr"] + max(block["size"], 1))
            for blocks in self.func_blocks.values()
            for block in blocks
        ]
        covered.sort()
        if not covered:
            return
        exec_ranges = (
            [(low, high) for low, high in self.pe.exec_ranges]
            if self.pe
            else []
        )
        # Code inside a real function's extent belongs to it even when no
        # block covers it (dead tails, alignment); IDA attributes it to the
        # function rather than making a new one.
        extents = sorted(
            (ea, ea + max(int(info.get("size") or 1), 1))
            for ea, info in self.functions.items()
        )
        extent_starts = [span[0] for span in extents]

        def in_extent(ea: int) -> bool:
            index = bisect.bisect_right(extent_starts, ea) - 1
            return (
                index >= 0
                and extents[index][0] <= ea < extents[index][1]
            )

        gaps = []
        cursor = min((low for low, _ in exec_ranges), default=covered[0][0])
        for low, high in covered:
            if low > cursor:
                gaps.append((cursor, low))
            cursor = max(cursor, high)
        gaps = [
            (low, high)
            for low, high in gaps
            if any(a <= low < b or a < high <= b for a, b in exec_ranges)
            and not in_extent(low)
            and high - low >= 3
        ]
        if not gaps:
            return
        script = ["e log.level=0"]
        for low, high in gaps:
            script.append("?e " + SECTION_PREFIX + "g:%x" % low)
            script.append("s 0x%x" % low)
            script.append("aoj %d" % min(high - low, 256))
        raw = self._run_script(script)
        data = _split_sections(raw)
        for low, high in gaps:
            decoded = []
            for document in _parse_json_stream(data.get("g:%x" % low) or ""):
                if isinstance(document, list):
                    decoded.extend(document)
            insns = sorted(
                (
                    insn
                    for insn in decoded
                    if low <= int(insn.get("addr") or 0) < high
                    and not _is_padding_insn(insn)
                ),
                key=lambda insn: insn["addr"],
            )
            if not insns:
                continue
            for insn in insns:
                self._register_instruction(insn)
            targets = {
                int(insn["jump"])
                for insn in insns
                if insn.get("jump") is not None
                and low <= int(insn["jump"]) < high
            }
            run: List[dict] = []
            previous = None
            for insn in insns:
                if (
                    run
                    and previous is not None
                    and (previous.get("type") or "") in _TERMINAL_TYPES
                    and int(insn["addr"]) not in targets
                ):
                    self._emit_gap_function(run)
                    run = []
                run.append(insn)
                previous = insn
            self._emit_gap_function(run)
        self.sorted_func_eas = sorted(self.functions)
        self._func_starts = list(self.sorted_func_eas)

    def _is_iat_thunk(self, insn: dict) -> bool:
        """True when ``insn`` is a lone ``jmp qword [IAT slot]`` thunk."""
        if (insn.get("type") or "") not in _JMP_TYPES:
            return False
        ops = insn.get("ops") or []
        if not ops:
            return False
        target = int(ops[0].get("value") or 0) or None
        if target is None:
            return False
        for lo, hi in getattr(self.pe, "iat_ranges", ()):
            if lo <= target < hi:
                return True
        return False

    def _emit_gap_function(self, run: List[dict]) -> None:
        """Register ``run`` as a function when it ends in a terminal."""
        if not run:
            return
        if (run[-1].get("type") or "") not in _TERMINAL_TYPES:
            return
        if len(run) == 1 and self._is_iat_thunk(run[0]):
            # ``jmp qword [IAT]`` entries are import thunks, not functions.
            return
        begin = int(run[0]["addr"])
        end = int(run[-1]["addr"]) + int(run[-1].get("size") or 1)
        self._add_funclet(begin, end, run)

    def _recover_gap_blocks(self) -> None:
        """Attribute referenced dead-code gaps inside functions to blocks.

        radare2 leaves regions inside a function's span unassigned when only
        an exception-continuation edge reaches them (e.g. an unwind cleanup
        path a funclet returns into).  IDA turns every referenced address
        into a block; do the same for decoded instructions that have an xref
        and belong to a function's extent but to no block.
        """
        covered: List[Tuple[int, int]] = []
        for blocks in self.func_blocks.values():
            for block in blocks:
                covered.append(
                    (block["addr"], block["addr"] + max(block["size"], 1))
                )
        if not covered:
            return
        covered.sort()
        starts = [span[0] for span in covered]

        def is_covered(address: int) -> bool:
            index = bisect.bisect_right(starts, address) - 1
            return index >= 0 and covered[index][0] <= address < covered[index][1]

        referenced = set(self.code_refs_to) | set(self.data_refs_to)
        order = sorted(self.insns)
        heads = [
            ea for ea in order if ea in referenced and not is_covered(ea)
        ]
        for head in heads:
            owner = self._function_for_address(head)
            if owner is None:
                continue
            members = []
            cursor = head
            while cursor in self.insns and not is_covered(cursor):
                members.append(cursor)
                insn = self.insns[cursor]
                if (insn.get("type") or "") in _STOP_FLOW_TYPES:
                    break
                index = bisect.bisect_right(order, cursor)
                cursor = order[index] if index < len(order) else None
            if not members:
                continue
            last = self.insns[members[-1]]
            last_t = last.get("type") or ""
            jump = fail = None
            if last_t in ("jmp", "cjmp"):
                jump = _int_or_none(last.get("jump"))
            if last_t not in _STOP_FLOW_TYPES:
                fail = _flow_successor(last)
            block = {
                "addr": head,
                "size": members[-1] + int(last.get("size") or 1) - head,
                "jump": jump,
                "fail": fail,
                "ninstr": len(members),
                "instrs": members,
            }
            blocks = self.func_blocks.setdefault(owner, [])
            blocks.append(block)
            blocks.sort(key=lambda b: b["addr"])
            # The recovered range now covers this head and its members.
            covered.append((block["addr"], block["addr"] + block["size"]))
            covered.sort()
            starts = [span[0] for span in covered]

    def _register_instruction(self, instruction: dict) -> None:
        address = int(instruction.get("addr") or 0)
        if not address:
            return
        size = int(instruction.get("size") or 0)
        raw_hex = instruction.get("bytes") or ""
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            raw = b""

        layout = capstone_operand_layout(raw, self.bits) if raw else None
        operands = []
        r2_operands = (instruction.get("opex") or {}).get("operands") or []
        if layout is None:
            layout = [
                {"type": _guess_ida_type(operand), "offb": 0} for operand in r2_operands
            ]

        is_flow = (instruction.get("type") or "") in _FLOW_INSTRUCTION_TYPES
        for index, operand in enumerate(r2_operands):
            entry = layout[index] if index < len(layout) else {"type": O_VOID, "offb": 0}
            operand_type = entry["type"]
            if is_flow and operand_type == O_IMM:
                # IDA reports branch/call targets as o_near, not o_imm; this
                # keeps jump targets out of the constants list, like Hex-Rays.
                operand_type = O_NEAR
            value = _operand_value(operand, instruction, self.bits)
            operands.append(
                {
                    "type": operand_type,
                    "offb": entry["offb"],
                    "value": value,
                    "addr": value if operand_type in OFFSET_OPERAND_TYPES else 0,
                    "reg": operand.get("base"),
                    "seg": operand.get("segment"),
                    "size": int(operand.get("size") or 0),
                }
            )

        decoded_size = size
        for operand in operands[:2]:
            if operand["type"] in OFFSET_OPERAND_TYPES:
                decoded_size -= operand["offb"]
        if decoded_size <= 0:
            decoded_size = 1

        instruction["raw_bytes"] = raw
        instruction["ops"] = operands
        instruction["decoded_size"] = min(decoded_size, max(size, 1))
        self.insns[address] = instruction

        jump = _int_or_none(instruction.get("jump"))
        if jump:
            refs = self.code_refs_from.setdefault(address, [])
            if jump not in refs:
                refs.append(jump)
            back = self.code_refs_to.setdefault(jump, [])
            if address not in back:
                back.append(address)
        if address + size:
            self.insn_ends[address + size] = address

        # Emulate IDA's data references: radare2 only reports explicit xref
        # edges, while IDA also marks memory operands with a computable target
        # (``lea reg, [rip+x]``, ``call qword [imp]``) as data references.
        # Stack-variable accesses would only be data references for the stack
        # slots IDA promotes to named variables, which is not reproducible
        # here, so they are intentionally left out.
        data_targets: List[int] = []
        for operand in operands:
            if operand["type"] not in (O_MEM, O_DISPL, O_PHRASE):
                continue
            base = (operand.get("reg") or "").lower()
            if (operand.get("seg") or "") in ("gs", "fs", "cs", "ds", "es", "ss"):
                continue
            if base in ("rip", "eip") or (not base and operand["addr"]):
                data_targets.append(operand["addr"])
        insn_type = instruction.get("type") or ""
        pointer = _int_or_none(instruction.get("ptr"))
        if insn_type in ("irjmp", "ujmp", "ijmp", "rjmp") and pointer is not None:
            # ``jmp qword [slot]``: IDA's code reference goes to the slot's
            # contents when they resolve to code; the slot itself stays a
            # data reference (already covered by afxj edges).
            raw_ptr = self.get_bytes(pointer, max(self.bits // 8, 4))
            if raw_ptr:
                resolved = int.from_bytes(raw_ptr, "little")
                if self._is_executable(resolved):
                    refs = self.code_refs_from.setdefault(address, [])
                    if resolved not in refs:
                        refs.append(resolved)
                    back = self.code_refs_to.setdefault(resolved, [])
                    if address not in back:
                        back.append(address)
        if data_targets:
            refs = self.data_refs_from.setdefault(address, [])
            for target in data_targets:
                if target not in refs:
                    refs.append(target)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _build_decompilation(text: str, xml: str) -> dict:
    """Turn one ``pdg``/``pdgx`` pair into the shape upstream expects."""
    cleaned = strip_ansi(text)
    lines = [line.rstrip() for line in cleaned.splitlines()]
    lines = [line for line in lines if line.strip()]
    lines = [line for line in lines if not line.lstrip().startswith("//")]

    prototype = lines[0].strip() if lines else None
    body = lines[1:] if len(lines) > 1 else []
    ast_nodes = parse_pdgx_codes(xml)

    return {
        "prototype": prototype,
        "lines": body,
        "ast": ast_nodes,
        "ok": prototype is not None,
    }


def parse_pdgx_codes(xml_text: str) -> List[int]:
    """Collect the ghidra p-code operation numbers of a ``pdgx`` document."""
    if not xml_text:
        return []
    start = xml_text.find("<result")
    if start < 0:
        start = xml_text.find("<function")
    if start < 0:
        return []
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml_text[start:])
    except Exception:
        return []
    codes = []
    for element in root.iter():
        if element.tag in ("op", "statement", "block"):
            value = element.get("code")
            if value:
                try:
                    codes.append(int(value, 0))
                except ValueError:
                    continue
    return codes


def _is_padding_insn(instruction: dict) -> bool:
    """True for filler bytes IDA never counts as instructions.

    MSVC pads funclets and function tails with ``int3`` (0xcc) and ``nop``
    (0x90); radare2 decodes them as instructions.
    """
    raw = instruction.get("raw_bytes")
    if raw is None:
        try:
            raw = bytes.fromhex(instruction.get("bytes") or "")
        except ValueError:
            raw = b""
    if raw and set(raw) <= {0x90, 0xCC}:
        return True
    return (instruction.get("type") or "") in ("invalid", "ill")


def _int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_name(name: str) -> str:
    if not name:
        return ""
    for prefix in _NAME_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    lowered = name.lower()
    for prefix in ("fcn.", "loc.", "sym.", "func."):
        if lowered.startswith(prefix):
            rest = name[len(prefix) :]
            if re.fullmatch(r"[0-9a-fA-F]+", rest):
                return "sub_" + rest.lower()
            return rest
    if name.lower().startswith("entry"):
        return name.lower() if name.lower() == "entry0" else name
    if name.startswith("imp."):
        return name[4:]
    return name


def _guess_ida_type(operand: dict) -> int:
    kind = operand.get("type")
    if kind == "reg":
        return O_REG
    if kind == "imm":
        return O_IMM
    if kind == "mem":
        if operand.get("base") and not operand.get("disp"):
            return O_PHRASE
        return O_DISPL
    return O_VOID


def _operand_value(operand: dict, instruction: dict, bits: int) -> int:
    mask = (1 << bits) - 1
    kind = operand.get("type")
    if kind == "imm":
        value = int(operand.get("value") or 0)
        if value < 0:
            return value & mask
        size = int(operand.get("size") or 0)
        # IDA sign-extends immediates narrower than the word size, e.g. an
        # imm32 of 0xC0000409 is reported as 0xFFFFFFFFC0000409 on x86-64.
        if 0 < size < max(bits // 8, 1) and value >= (1 << (size * 8 - 1)):
            return value | (mask ^ ((1 << (size * 8)) - 1))
        return value
    if kind == "mem":
        base = operand.get("base")
        disp = int(operand.get("disp") or 0)
        if base in ("rip", "pc"):
            return int(instruction.get("addr") or 0) + int(
                instruction.get("size") or 0
            ) + disp
        if not base:
            return disp & mask
        # Register-based displacement: disp is a signed 32-bit value.
        if disp < 0:
            return disp & mask
        if 0x80000000 <= disp <= 0xFFFFFFFF:
            return disp | (mask & ~0xFFFFFFFF)
        return disp
    return -1


def _operand_address(operand: dict, instruction: dict, bits: int) -> int:
    kind = operand.get("type")
    if kind != "mem":
        return 0
    return _operand_value(operand, instruction, bits)


def _flow_successor(instruction: Optional[dict]) -> Optional[int]:
    """Return the fall-through target of ``instruction`` or ``None``.

    Mirrors IDA's notion of an instruction "passing flow": radare2 reports it
    explicitly through the ``fail`` key for branch instructions, while regular
    instructions implicitly flow to ``addr + size``.
    """
    if not instruction:
        return None
    fail = _int_or_none(instruction.get("fail"))
    if fail:
        return fail
    if (instruction.get("type") or "") in _STOP_FLOW_TYPES:
        return None
    size = int(instruction.get("size") or 0)
    if size <= 0:
        return None
    return int(instruction.get("addr") or 0) + size
