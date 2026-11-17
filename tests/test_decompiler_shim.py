import json

from r2diaphora.ida_shim import ida_hexrays, state
from r2diaphora.ida_shim.cache import (
    R2BinaryCache,
    _build_decompilation,
    _build_pdc_decompilation,
)
from r2diaphora.ida_shim.decompiler import decompile_with_r2
from r2diaphora.upstream.jkutils.factor import primesbelow

CALC = r"C:\Windows\System32\calc.exe"


class DummyAstVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.primes = primesbelow(4096)
        self.primes_hash = 1

    def visit_expr(self, expr):
        self.primes_hash *= self.primes[expr.op]
        return 0

    def visit_insn(self, ins):
        self.primes_hash *= self.primes[ins.op]
        return 0


def test_build_decompilation_handles_malformed_or_nonjson_output():
    # Non-JSON warning lines or empty output must not raise
    entry = _build_decompilation("WARNING: some r2 message\nnot json")
    assert entry == {"prototype": None, "lines": [], "ast": [], "ok": False}
    assert _build_decompilation("")["ok"] is False


def test_build_decompilation_reads_real_pdgj_doc():
    code = "\nvoid fcn.140001000(void)\n\n{\n    fcn.140002000();\n    return;\n}\n"
    # "fcn.140002000" spans chars 35..47 of code
    target = "fcn.140002000"
    start = code.index(target)
    doc = {
        "code": code,
        "annotations": [
            {
                "start": start,
                "end": start + len(target),
                "type": "function_name",
                "name": target,
                "offset": 0x140002000,
            }
        ],
        "pcode_ops": [
            {"opcode": 64, "is_dead": False},
            {"opcode": 7, "is_dead": False},
            {"opcode": 66, "is_dead": True},
        ],
    }
    resolved = {}
    entry = _build_decompilation(
        json.dumps(doc),
        resolve_name=lambda name, off: resolved.setdefault(
            off, "sub_%x" % off
        ),
    )
    assert entry["ok"] is True
    assert entry["prototype"] == "void fcn.140001000(void)"
    assert "    sub_140002000();" in entry["lines"]
    assert "fcn.140002000" not in "\n".join(entry["lines"])
    # Dead ops are excluded from the hash material
    assert entry["ast"] == [64, 7]


def test_build_decompilation_without_resolver_keeps_raw_names():
    code = "void f(void)\n{\n    fcn.140002000();\n}\n"
    start = code.index("fcn.140002000")
    doc = {
        "code": code,
        "annotations": [
            {
                "start": start,
                "end": start + len("fcn.140002000"),
                "type": "function_name",
                "name": "fcn.140002000",
                "offset": 0x140002000,
            }
        ],
        "pcode_ops": [{"opcode": 5, "is_dead": False}],
    }
    entry = _build_decompilation(json.dumps(doc))
    assert entry["ok"] is True
    assert entry["ast"] == [5]


def test_build_pdc_decompilation_parses_text_output():
    section = (
        "// r2dec pseudo code output\n"
        "function fcn.140002000 () {\n"
        "    sym.imp.Kernel32.dll_GetVersion();\n"
        "    return 0;\n"
        "}\n"
    )
    tree = (
        "seq 0x140002000\n"
        "  bb 0x140002000\n"
        "  if 0x140002010\n"
        "    bb 0x140002020\n"
        "  return 0x140002030\n"
    )
    entry = _build_pdc_decompilation(section, tree)
    assert entry["ok"] is True
    assert entry["prototype"] == "function sub_140002000 () {"
    assert "    dll_GetVersion();" in entry["lines"]
    # the pdct region tree feeds the primes hash: seq,bb,if,bb,return
    assert entry["ast"] == [1, 2, 3, 2, 16]
    # without a pdct dump the ast just stays empty
    assert _build_pdc_decompilation(section)["ast"] == []
    assert _build_pdc_decompilation("   \n\n")["ok"] is False


def test_decompile_and_ast_visitor_on_calc_exe():
    cache = R2BinaryCache(CALC, load_pdb=False)
    state.set_active_cache(cache)
    try:
        cfunc = decompile_with_r2(cache, 0x1400017CC)
        assert cfunc is not None
        sv = cfunc.get_pseudocode()
        assert len(sv) > 3
        assert cfunc.entry_ea == 0x1400017CC
        visitor = DummyAstVisitor()
        visitor.apply_to(cfunc.body, None)
        assert visitor.primes_hash > 1
        # A second lookup must not run radare2 again
        cmds = cache.cmd_count
        again = ida_hexrays.decompile(0x1400017CC)
        assert again is not None
        assert cache.cmd_count == cmds
    finally:
        state.set_active_cache(None)
        cache.close()


def test_decompile_all_batches_every_function():
    cache = R2BinaryCache(CALC, load_pdb=False)
    try:
        before = cache.cmd_count
        cache.decompile_all()
        assert cache.cmd_count == before + 1
        assert cache.decompiler_available is True
        assert len(cache.decompiled) == len(cache.functions)
    finally:
        cache.close()
