"""r2ghidra ``pdgj`` backed replacement for the Hex-Rays pieces Diaphora uses."""

from typing import List, Optional

from r2diaphora.ida_shim.cache import clean_r2_pseudocode_line

# Hex-Rays ctree expression/statement op codes are only used by Diaphora as
# stable indexes into a prime table, so a literal copy of IDA's table is not
# required; what matters is that every node has a deterministic small number.
EXPR_DEFS = {}

_CTREE_OPS = [
    "cot_empty",
    "cot_comma",
    "cot_asg",
    "cot_asgbor",
    "cot_asgxor",
    "cot_asgband",
    "cot_asgadd",
    "cot_asgsub",
    "cot_asmul",
    "cot_asgdiv",
    "cot_asgmod",
    "cot_asgshl",
    "cot_asgshr",
    "cot_asgushr",
    "cot_asgand",
    "cot_asgor",
    "cot_add",
    "cot_sub",
    "cot_mul",
    "cot_div",
    "cot_sdiv",
    "cot_udiv",
    "cot_mod",
    "cot_smod",
    "cot_umod",
    "cot_fadd",
    "cot_fsub",
    "cot_fmul",
    "cot_fdiv",
    "cot_neg",
    "cot_bnot",
    "cot_lnot",
    "cot_bor",
    "cot_xor",
    "cot_band",
    "cot_shl",
    "cot_shr",
    "cot_ushr",
    "cot_eq",
    "cot_ne",
    "cot_slt",
    "cot_sle",
    "cot_sgt",
    "cot_sge",
    "cot_ult",
    "cot_ule",
    "cot_ugt",
    "cot_uge",
    "cot_land",
    "cot_lor",
    "cot_ref",
    "cot_deref",
    "cot_idx",
    "cot_memptr",
    "cot_memref",
    "cot_num",
    "cot_fnum",
    "cot_str",
    "cot_obj",
    "cot_var",
    "cot_insn",
    "cot_cast",
    "cot_lambda",
    "cot_helper",
    "cot_type",
    "cit_empty",
    "cit_block",
    "cit_expr",
    "cit_if",
    "cit_for",
    "cit_while",
    "cit_do",
    "cit_switch",
    "cit_break",
    "cit_continue",
    "cit_return",
    "cit_goto",
    "cit_asm",
    "cit_tailcall",
    "cit_end",
]
for _index, _name in enumerate(_CTREE_OPS):
    EXPR_DEFS[_name] = _index


class MockLine:
    """One pseudocode line, mirroring ``strvec_t``'s items."""

    __slots__ = ("line",)

    def __init__(self, line: str):
        self.line = line

    def __repr__(self):
        return f"MockLine({self.line!r})"


class MockNode:
    __slots__ = ("op", "kids", "is_insn")

    def __init__(self, op: int, kids: Optional[List["MockNode"]] = None, is_insn: bool = False):
        self.op = op
        self.kids = kids or []
        self.is_insn = is_insn

    def __repr__(self):
        return f"MockNode(op={self.op}, kids={len(self.kids)})"


class MockCFunc:
    """The subset of ``cfunc_t`` that Diaphora touches."""

    def __init__(self, entry_ea: int, prototype: Optional[str], lines: List[str], ast: List[int]):
        self.entry_ea = entry_ea
        self.prototype = prototype
        self._lines = [MockLine(line) for line in lines]
        if prototype is not None:
            self._lines.insert(0, MockLine(prototype))
        # Diaphora only needs a stable tree of small integers to fold into its
        # pseudocode hash; the ghidra p-code operation numbers are exactly that.
        self.body = MockNode(
            op=EXPR_DEFS["cit_block"],
            kids=[MockNode(op=code, is_insn=True) for code in ast],
        )
        self.ast = ast

    def get_pseudocode(self) -> List[MockLine]:
        return list(self._lines)

    def __repr__(self):
        return f"MockCFunc(entry_ea=0x{self.entry_ea:x}, lines={len(self._lines)})"


def decompile_with_r2(cache, ea: int, timeout: float = 15.0) -> Optional[MockCFunc]:
    """Decompile ``ea`` through the cache (batch decompilation, no IPC here)."""
    func_ea = ea
    if hasattr(ea, "start_ea"):
        func_ea = int(ea.start_ea)
    entry = cache.get_decompiled(func_ea)
    if entry is None or not entry.get("ok"):
        return None
    lines = [clean_r2_pseudocode_line(line) for line in entry["lines"]]
    prototype = entry["prototype"]
    if prototype is not None:
        prototype = clean_r2_pseudocode_line(prototype)
    return MockCFunc(func_ea, prototype, lines, entry["ast"])
