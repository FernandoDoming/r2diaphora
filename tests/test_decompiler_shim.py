from r2diaphora.ida_shim import ida_hexrays, state
from r2diaphora.ida_shim.cache import R2BinaryCache
from r2diaphora.ida_shim.decompiler import decompile_with_r2, parse_pdgx_xml_to_ast
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


def test_parse_pdgx_handles_malformed_or_prefixed_xml():
    # Review Focus #4: non-XML warning lines or empty output must not raise
    proto, lines, nodes = parse_pdgx_xml_to_ast("WARNING: some r2 message\nnot xml")
    assert proto is None
    assert lines == []
    assert nodes == []


def test_parse_pdgx_reads_real_xml():
    xml = (
        "<result><function><funcname>int f(void)</funcname>"
        "<syntax>return 0;</syntax><op code=\"3\"></op><op code=\"5\"></op>"
        "</function></result>"
    )
    proto, lines, nodes = parse_pdgx_xml_to_ast(xml)
    assert proto == "int f(void)"
    assert lines == ["return 0;"]
    assert nodes == [("expr", 3), ("expr", 5)]


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
