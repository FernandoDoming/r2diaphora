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

    def __init__(self, image_base: int, sections: List[dict]):
        self.image_base = image_base
        self.sections = sections

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
    except (struct.error, IndexError):
        return None
    return PEInfo(image_base, sections)


def parse_pdata_entries(
    pdata_bytes: bytes, image_base: int, exec_ranges: List[Tuple[int, int]]
) -> List[int]:
    """Return the function starts of a PE64 ``.pdata`` directory.

    ``.pdata`` is page aligned, so after the real ``RUNTIME_FUNCTION`` entries
    there is a zero-filled tail; entries whose begin/end are zero, inverted or
    outside an executable section are padding or data and are skipped.
    """
    starts: List[int] = []
    for offset in range(0, len(pdata_bytes) - 11, 12):
        begin, end, _unwind = struct.unpack_from("<III", pdata_bytes, offset)
        if begin == 0 or end == 0 or end <= begin:
            continue
        start = image_base + begin
        if not any(low <= start < high for low, high in exec_ranges):
            continue
        starts.append(start)
    return starts


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
        self.cmd_count = 0

        self.pe = parse_pe(self.input_path)
        self.image_base = self.pe.image_base if self.pe else 0
        self.bits = 64 if self.image_base > 0xFFFFFFFF else 32
        self.arch = "x86"
        self.idp_name = "metapc"
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
        self.switches_by_insn: Dict[int, Tuple[int, List[int]]] = {}
        self.segments: List[dict] = []

        self._segments_bytes: List[Tuple[int, bytes]] = []
        self._func_starts: List[int] = []
        self._closed = False

        self._build()

    # -- public API ---------------------------------------------------------

    def close(self) -> None:
        self._closed = True
        self._segments_bytes = []
        self.insns = {}

    def ensure_function_cached(self, func_ea: int) -> dict:
        func = self.functions.get(func_ea)
        if func is None:
            raise KeyError("Unknown function at 0x%x" % func_ea)
        return func

    def get_insn(self, ea: int) -> Optional[dict]:
        return self.insns.get(ea)

    def get_blocks(self, func_ea: int) -> List[dict]:
        return self.func_blocks.get(func_ea, [])

    def get_bytes(self, ea: int, size: int) -> bytes:
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

    def get_code_refs_from(self, ea: int) -> List[int]:
        return self.code_refs_from.get(ea, [])

    def get_code_refs_to(self, ea: int) -> List[int]:
        return self.code_refs_to.get(ea, [])

    def get_data_refs_from(self, ea: int) -> List[int]:
        return self.data_refs_from.get(ea, [])

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

    # -- loading ------------------------------------------------------------

    def _file_md5(self) -> str:
        digest = hashlib.md5()
        with open(self.input_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _pdata_seeds(self) -> List[int]:
        if self.pe is None or self.bits != 64:
            return []
        raw = self.pe.read_section(self.input_path, ".pdata")
        if not raw:
            return []
        return parse_pdata_entries(raw, self.pe.image_base, self.pe.exec_ranges)

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
                timeout=3600,
            )
            return completed.stdout.decode("utf-8", "replace")
        finally:
            try:
                os.remove(script_path)
            except OSError:
                pass

    def _build(self) -> None:
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
            for index, section in enumerate(self.pe.sections):
                if not section["exec"] or section["vsize"] == 0:
                    continue
                sections.append(
                    ("memory%d" % index, "p8 %d @ 0x%x" % (section["vsize"], section["vaddr"]))
                )

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
        for name in list(data):
            if name.startswith("memory"):
                self._parse_memory(name, data[name])

        self._load_instructions()

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
            self.idp_name = "metapc"
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
            normalized = _normalize_name(name)
            if not normalized:
                continue
            existing = self.names.get(address)
            if existing is not None and not existing[0].startswith("sub_"):
                continue
            self.names[address] = (normalized, name, None)

    def _parse_callgraph(self, callgraph_stream: List[Any]) -> None:
        for entry in callgraph_stream:
            for edge in entry or []:
                source = _int_or_none(edge.get("from"))
                target = _int_or_none(edge.get("to"))
                if source is None or target is None:
                    continue
                refs = self.code_refs_from.setdefault(source, [])
                if target not in refs:
                    refs.append(target)
                back = self.code_refs_to.setdefault(target, [])
                if source not in back:
                    back.append(source)
                if edge.get("type") not in ("CALL", "CODE", "JMP", "UJMP", "CJMP"):
                    data = self.data_refs_from.setdefault(source, [])
                    if target not in data:
                        data.append(target)

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

        for index, operand in enumerate(r2_operands):
            entry = layout[index] if index < len(layout) else {"type": O_VOID, "offb": 0}
            operands.append(
                {
                    "type": entry["type"],
                    "offb": entry["offb"],
                    "value": _operand_value(operand, instruction, self.bits),
                    "addr": _operand_address(operand, instruction, self.bits),
                    "reg": operand.get("base"),
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

        for ref in _flow_targets(instruction):
            refs = self.code_refs_from.setdefault(address, [])
            if ref not in refs:
                refs.append(ref)
            back = self.code_refs_to.setdefault(ref, [])
            if address not in back:
                back.append(address)


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
    kind = operand.get("type")
    if kind == "imm":
        return int(operand.get("value") or 0)
    if kind == "mem":
        return int(operand.get("disp") or 0)
    return 0


def _operand_address(operand: dict, instruction: dict, bits: int) -> int:
    kind = operand.get("type")
    base = operand.get("base")
    disp = int(operand.get("disp") or 0)
    if kind != "mem":
        return 0
    if base in ("rip", "pc"):
        return int(instruction.get("addr") or 0) + int(instruction.get("size") or 0) + disp
    if not base:
        return disp
    return 0


def _flow_targets(instruction: dict) -> List[int]:
    targets = []
    for key in ("jump", "fail"):
        value = _int_or_none(instruction.get(key))
        if value:
            targets.append(value)
    return targets
