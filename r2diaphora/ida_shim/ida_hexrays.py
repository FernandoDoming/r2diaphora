"""Headless stand-in for IDA's ``ida_hexrays`` module."""

from typing import Any, List, Optional

from r2diaphora.ida_shim import state
from r2diaphora.ida_shim.decompiler import EXPR_DEFS, MockCFunc, MockNode, decompile_with_r2

CV_FAST = 0x0001
DECOMP_NO_WAIT = 0x0001
DECOMP_WARNINGS = 0x0002
MMAT_GENERATED = 0x0001
BLT_STOP = 0


class ctree_visitor_t:
    """Depth-first walker with the same call surface as IDA's visitor."""

    def __init__(self, flags: int = 0):
        self.flags = flags

    def visit_expr(self, expr: MockNode) -> int:  # pragma: no cover - overridden
        return 0

    def visit_insn(self, ins: MockNode) -> int:  # pragma: no cover - overridden
        return 0

    def apply_to(self, item: Any, parent: Any = None) -> int:
        stack: List[MockNode] = []
        if item is not None:
            stack.append(item)
        while stack:
            node = stack.pop()
            if getattr(node, "is_insn", False):
                if self.visit_insn(node):
                    return 1
            else:
                if self.visit_expr(node):
                    return 1
            stack.extend(reversed(node.kids))
        return 0


def decompile(ea_or_func: Any, flags: int = 0) -> Optional[MockCFunc]:
    if not state.has_active_cache():
        return None
    cache = state.get_active_cache()
    func_ea = getattr(ea_or_func, "start_ea", ea_or_func)
    return decompile_with_r2(cache, int(func_ea))


def init_hexrays_plugin(flags: int = 0) -> bool:
    if not state.has_active_cache():
        return False
    cache = state.get_active_cache()
    if cache.decompiler_available is None:
        cache.decompile_all()
    return bool(cache.decompiler_available)


def gen_microcode(*args, **kwargs):
    """Diaphora supports builds without microcode; we never emit any."""
    return None


def mark_cfunc_dirty(*args, **kwargs) -> None:
    return None


def clear_cached_cfuncs() -> None:
    if state.has_active_cache():
        state.get_active_cache().decompiled.clear()


class vd_printer_t:
    def __init__(self, *args, **kwargs):
        pass

    def print_line(self, *args, **kwargs):
        return 0


class qstring_printer_t(vd_printer_t):
    pass


class mba_ranges_t:
    def __init__(self, *args, **kwargs):
        self.args = args


class mlist_t:
    def __init__(self, *args, **kwargs):
        pass


class hexrays_failure_t:
    def __init__(self, code: int = 0, ea: int = 0, str: str = ""):
        self.code = code
        self.errea = ea
        self.str = str

    def desc(self) -> str:
        return self.str


def get_mba(*args, **kwargs):
    return None
