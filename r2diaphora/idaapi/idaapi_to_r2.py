import os
from sys import stderr
import time
import logging
import r2pipe
import platform

import subprocess
from subprocess import Popen
from pycparser import CParser, c_ast

from r2diaphora.jkutils.factor import primesbelow as primes
from .instructions import CPU_INSTRUCTIONS

LOG_FORMAT = "%(asctime)-15s [%(levelname)s] - %(message)s"
log = logging.getLogger("diaphora.idaconv")
log.setLevel(logging.DEBUG)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter(LOG_FORMAT)
console.setFormatter(formatter)
log.addHandler(console)

#-----------------------------------------------------------------------
BADADDR = 0xFFFFFFFFFFFFFFFF
r2 = None

#-------------------------------------------------------------------------------
EXPR_DEFS = {
    "cot_empty"    : 0,
    "cot_comma"    : 1,   # x, y
    "cot_asg"      : 2,   # x = y
    "cot_asgbor"   : 3,   # x |= y
    "cot_asgxor"   : 4,   # x ^= y
    "cot_asgband"  : 5,   # x &= y
    "cot_asgadd"   : 6,   # x += y
    "cot_asgsub"   : 7,   # x -= y
    "cot_asgmul"   : 8,   # x *= y
    "cot_asgsshr"  : 9,   # x >>= y signed
    "cot_asgushr"  : 10,  # x >>= y unsigned
    "cot_asgshl"   : 11,  # x <<= y
    "cot_asgsdiv"  : 12,  # x /= y signed
    "cot_asgudiv"  : 13,  # x /= y unsigned
    "cot_asgsmod"  : 14,  # x %= y signed
    "cot_asgumod"  : 15,  # x %= y unsigned
    "cot_tern"     : 16,  # x ? y : z
    "cot_lor"      : 17,  # x || y
    "cot_land"     : 18,  # x && y
    "cot_bor"      : 19,  # x | y
    "cot_xor"      : 20,  # x ^ y
    "cot_band"     : 21,  # x & y
    "cot_eq"       : 22,  # x == y int or fpu (see EXFL_FPOP)
    "cot_ne"       : 23,  # x != y int or fpu (see EXFL_FPOP)
    "cot_sge"      : 24,  # x >= y signed or fpu (see EXFL_FPOP)
    "cot_uge"      : 25,  # x >= y unsigned
    "cot_sle"      : 26,  # x <= y signed or fpu (see EXFL_FPOP)
    "cot_ule"      : 27,  # x <= y unsigned
    "cot_sgt"      : 28,  # x >  y signed or fpu (see EXFL_FPOP)
    "cot_ugt"      : 29,  # x >  y unsigned
    "cot_slt"      : 30,  # x <  y signed or fpu (see EXFL_FPOP)
    "cot_ult"      : 31,  # x <  y unsigned
    "cot_sshr"     : 32,  # x >> y signed
    "cot_ushr"     : 33,  # x >> y unsigned
    "cot_shl"      : 34,  # x << y
    "cot_add"      : 35,  # x + y
    "cot_sub"      : 36,  # x - y
    "cot_mul"      : 37,  # x * y
    "cot_sdiv"     : 38,  # x / y signed
    "cot_udiv"     : 39,  # x / y unsigned
    "cot_smod"     : 40,  # x % y signed
    "cot_umod"     : 41,  # x % y unsigned
    "cot_fadd"     : 42,  # x + y fp
    "cot_fsub"     : 43,  # x - y fp
    "cot_fmul"     : 44,  # x * y fp
    "cot_fdiv"     : 45,  # x / y fp
    "cot_fneg"     : 46,  # -x fp
    "cot_neg"      : 47,  # -x
    "cot_cast"     : 48,  # (type)x
    "cot_lnot"     : 49,  # !x
    "cot_bnot"     : 50,  # ~x
    "cot_ptr"      : 51,  # *x, access size in 'ptrsize'
    "cot_ref"      : 52,  # &x
    "cot_postinc"  : 53,  # x++
    "cot_postdec"  : 54,  # x--
    "cot_preinc"   : 55,  # ++x
    "cot_predec"   : 56,  # --x
    "cot_call"     : 57,  # x(...)
    "cot_idx"      : 58,  # x[y]
    "cot_memref"   : 59,  # x.m
    "cot_memptr"   : 60,  # x->m, access size in 'ptrsize'
    "cot_num"      : 61,  # n
    "cot_fnum"     : 62,  # fpc
    "cot_str"      : 63,  # string constant
    "cot_obj"      : 64,  # obj_ea
    "cot_var"      : 65,  # v
    "cot_insn"     : 66,  # instruction in expression, internal representation only
    "cot_sizeof"   : 67,  # sizeof(x)
    "cot_helper"   : 68,  # arbitrary name
    "cot_type"     : 69,  # arbitrary type
    "cit_empty"    : 70,  # instruction types start here
    "cit_block"    : 71,  # block-statement: { ... }
    "cit_expr"     : 72,  # expression-statement: expr;
    "cit_if"       : 73,  # if-statement
    "cit_for"      : 74,  # for-statement
    "cit_while"    : 75,  # while-statement
    "cit_do"       : 76,  # do-statement
    "cit_switch"   : 77,  # switch-statement
    "cit_break"    : 78,  # break-statement
    "cit_continue" : 79,  # continue-statement
    "cit_return"   : 80,  # return-statement
    "cit_goto"     : 81,  # goto-statement
    "cit_asm"      : 82,  # asm-statement
}
#-------------------------------------------------------------------------------
class CAstVisitor(c_ast.NodeVisitor):
    def __init__(self):
        self.primes      = primes(4096)
        self.primes_hash = 1
        self.cfunc       = None
        self.ast         = None
        return

    def apply_to(self, pseudo):
        self.cfunc = pseudo
        if self.build_ast():
            self.visit(self.ast.ext[-1])

    def build_ast(self):
        pseudo = f"""
        #include <stdlib.h>

        {self.cfunc}
        """
        dirname  = os.path.dirname(__file__)
        libdir = os.path.abspath(
            os.path.join(dirname, "..", "pycparser", "fake_libc_include")
        )
        parser = CParser()

        try:
            p = Popen(
                ["gcc", "-nostdinc", "-E", f"-I{libdir}", "-xc", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = p.communicate(bytes(pseudo, "utf-8"))
            self.ast = parser.parse(stdout.decode("utf-8"))
            return True

        except Exception:
            # log.exception(f"Could not obtain AST for {pseudo}")
            return False

    def visit_FuncCall(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cot_call"]]

    def visit_If(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_if"]]

    def visit_For(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_for"]]

    def visit_While(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_while"]]

    def visit_DoWhile(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_do"]]

    def visit_Switch(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_switch"]]

    def visit_Break(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_break"]]

    def visit_Continue(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_continue"]]

    def visit_Assignment(self, node):
        if node.op == "=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asg"]]
        elif node.op == "|=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgbor"]]
        elif node.op == "^=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgxor"]]
        elif node.op == "&=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgband"]]
        elif node.op == "+=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgadd"]]
        elif node.op == "-=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgsub"]]
        elif node.op == "*=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgmul"]]
        elif node.op == ">>=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgsshr"]]
        elif node.op == "<<=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgshl"]]
        elif node.op == "/=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgsdiv"]]
        elif node.op == "%=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_asgsmod"]]

    def visit_TernaryOp(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cot_tern"]]

    def visit_BinaryOp(self, node):
        if node.op == "+":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_add"]]
        elif node.op == "-":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_sub"]]
        elif node.op == "*":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_mul"]]
        elif node.op == "/":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_sdiv"]]
        elif node.op == "%":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_smod"]]
        elif node.op == ">":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_sgt"]]
        elif node.op == "<":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_slt"]]
        elif node.op == ">>":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_sshr"]]
        elif node.op == "<<":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_shl"]]
        elif node.op == "^":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_xor"]]
        elif node.op == "&":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_band"]]
        elif node.op == "&&":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_land"]]
        elif node.op == "|":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_bor"]]
        elif node.op == "||":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_lor"]]
        elif node.op == "==":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_eq"]]
        elif node.op == "!=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_ne"]]
        elif node.op == ">=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_sge"]]
        elif node.op == "<=":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_sle"]]

    def visit_UnaryOp(self, node):
        if node.op == "sizeof":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_sizeof"]]
        elif node.op == "p++":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_postinc"]]
        elif node.op == "p--":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_postdec"]]
        elif node.op == "++p":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_preinc"]]
        elif node.op == "--p":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_predec"]]
        elif node.op == "!":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_lnot"]]
        elif node.op == "&":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_ref"]]
        elif node.op == "~":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_bnot"]]
        elif node.op == "*":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_ptr"]]

    def visit_ArrayRef(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cot_idx"]]

    def visit_StructRef(self, node):
        if node.type == ".":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_memref"]]
        elif node.type == "->":
            self.primes_hash *= self.primes[EXPR_DEFS["cot_memptr"]]

    def visit_Return(self, node):
        self.primes_hash *= self.primes[EXPR_DEFS["cit_return"]]

#-----------------------------------------------------------------------
def log_exec_r2_cmdj(cmd):
    s = time.time()
    r = r2.cmdj(cmd)
    log.debug(f"R2 CMDJ: {cmd}: {time.time() - s}s")
    return r

def log_exec_r2_cmd(cmd):
    s = time.time()
    r = r2.cmd(cmd)
    log.debug(f"R2 CMD: {cmd}: {time.time() - s}s")
    return r

#-----------------------------------------------------------------------
_no_ret_fns = None
def no_ret_functions():
    global _no_ret_fns
    if _no_ret_fns:
        return _no_ret_fns

    _no_ret_fns = log_exec_r2_cmd("tn").split("\n")
    return _no_ret_fns

_all_fns = None
def get_all_fns(exclude_libs = False):
    global _all_fns
    if _all_fns:
        if exclude_libs:
            return [fn for fn in _all_fns if not fn["name"].startswith("flirt.")]
        else:
            return _all_fns

    _all_fns = log_exec_r2_cmdj("aflj")
    if exclude_libs:
        return [fn for fn in _all_fns if not fn["name"].startswith("flirt.")]
    else:
        return _all_fns

def scan_libs():
    sigs_dir = os.path.join(os.path.expanduser("~"), ".r2diaphora", "signatures", "flirt")
    if os.path.isdir(sigs_dir):
        log_exec_r2_cmd(f"zfs {sigs_dir}/*.sig")

def get_function_name(ea):
    try:
        return log_exec_r2_cmdj(f"fd.j @ {ea}")[0]
    except Exception:
        return {}

def get_flag_at_addr(ea):
    return log_exec_r2_cmdj(f"fdj @ {ea}")

def is_func(ea):
    return bool(log_exec_r2_cmdj(f"fd.j @ {ea}"))

def test_addr_within_function(f, ea):
    fn = get_func(f)
    if not fn:
        return False

    return ea >= fn["offset"] and ea <= (fn["offset"] + fn["size"])

#-----------------------------------------------------------------------
def get_arch():
    return log_exec_r2_cmdj("ij").get("bin", {}).get("arch")

#-----------------------------------------------------------------------
def strings():
    return log_exec_r2_cmdj("izj")

def string_values(min_str_len = 1):
    r2_strs = strings()
    strs = set()
    for s in r2_strs:
        v = s["string"]
        if len(v) >= min_str_len:
            strs.add(v)
    return list(strs)


#-----------------------------------------------------------------------
def block_succs(addr):
    res = []
    try:
        bb = log_exec_r2_cmdj("afbj. @ %s" % (addr))
    except Exception:
        log.error("NO BASIC BLOCK AT %s"%(addr))
        return res

    bb = bb[0]
    try:
        res.append(int(bb["jump"]))
    except Exception:
        pass
    try:
        res.append(int(bb["fail"]))
    except Exception:
        pass
    return res

def block_preds(addr):
    res = set()
    try:
        bbs = log_exec_r2_cmdj("afbj @ %s"%(addr))
    except Exception:
        log.error("NO BASIC BLOCKS FOR %s"%(addr))
        return res

    if not bbs:
        log.warn("EMPTY BB LIST FOR %s"%(addr))
        return res

    for bb in bbs:
        if bb.get("jump") == addr or bb.get("fail") == addr:
            res.add(bb["addr"])
    return list(res)

def GetMaxLocalType():
    # It's used, in IDA, to return the total number of structs, enums and
    # unions. I doubt there is something similar in r2.
    return int(log_exec_r2_cmd('t~?'))

def get_switch_info_ex(ea):
    # TODO
    return []

def int16(x):
    try:
        return int(x, 16)
    except Exception:
        if x != "":
            log.error("ERROR converting %s"%(x))
        return 0

def GetLocalTypeName(x):
    return ""

def GetString(ea, lenght, type):
    return log_exec_r2_cmd(f"ps @ {ea}")

#-----------------------------------------------------------------------
def CodeRefsTo(x, _):
    # Return a list of code references to address 'x'. The value 'y',
    # in IDA, is used to consider the previous instruction (y=1) as a valid
    # code reference or if it should be ignored (y=0).
    xrefs = log_exec_r2_cmd(f"axtq. @ {x}").strip()
    if xrefs == "":
        return []

    return [int16(xref) for xref in xrefs.split("\n")]

def CodeRefsFrom(x, _):
    xrefs = log_exec_r2_cmd(f"axfq. @ {x}").strip()
    if xrefs == "":
        return []

    return [int16(xref) for xref in xrefs.split("\n")]

def DataRefsFrom(x):
    return log_exec_r2_cmdj(f"axfj @ {x}")

def GetOperandValue(ea, n):
    # Get number used in the operand
    # This function returns an immediate number used in the operand

    #     Parameters:
    # ea - linear address of instruction
    # n - the operand number
    #     Returns:
    # value operand is an immediate value => immediate value
    # operand has a displacement => displacement 
    # operand is a direct memory ref => memory address 
    # operand is a register => register number 
    # operand is a register phrase => phrase number 
    # otherwise => -1

    _in = log_exec_r2_cmdj(f"aoj 1 @ {ea}")
    try:
        op = _in[0]["opex"]["operands"][n]
    except (KeyError, IndexError):
        return -1

    if op["type"] == "imm":
        return op["value"]
    elif op["type"] == "reg":
        return -1
    elif op["type"] == "mem":
        return op["disp"]
    else:
        return -1

#-----------------------------------------------------------------------
def r2_get_imagebase():
    #ep = ((int(r2.cmd("ieq"), 16) >> 24) << 24)
    ep = int(log_exec_r2_cmd("ia~baddr[1]"), 16)
    return ep

#-----------------------------------------------------------------------
def r2_get_idp_name():
    # idaapi.get_idp_name() returns the current processor (CPU arch)
    # of the opened binary.
    return log_exec_r2_cmd('ij~{core.arch}')
    #return r2.cmd('e asm.arch')

#-----------------------------------------------------------------------
def GetStructIdByName(x):
    # Relevant to structs: get the internal id of a struct by its name.
    return None

#-----------------------------------------------------------------------
def decompile(ea, decompiler_command = "pdg"):
    return log_exec_r2_cmd(f"{decompiler_command} @ {ea}")

#-----------------------------------------------------------------------
def get_func(ea):
    # In IDA, it should return a "function object". Mostly specific to get
    # the start and end address, as well as the size, etc...

    # fns = log_exec_r2_cmdj(f"afij @ {ea}")
    # if fns and len(fns) > 0:
    #     return fns[0]
    # else:
    #     return None

    # afi is slow, this method is faster, even it does not look like it
    return next(filter(lambda fn: fn["offset"] == ea, get_all_fns()), {})

#-----------------------------------------------------------------------
def GetInstructionList():
    arch = log_exec_r2_cmdj("ij").get("bin", {}).get("arch", "")
    return CPU_INSTRUCTIONS.get(arch, [])

#-----------------------------------------------------------------------
def Heads(ea, size):
    # res = log_exec_r2_cmd(f"pid {size} @ {ea}~[0]").strip()
    # addrs = filter(None, [int16(x) for x in res.split("\n")])
    # # Remove duplicates
    # return list(dict.fromkeys(addrs))
    ops = log_exec_r2_cmdj(f"aoj {size} @ {ea}")
    return [op["addr"] for op in ops]

def GetCommentEx(x, type):
    return log_exec_r2_cmd("CC.@ %s"%(x))

def diaphora_decode(x):
    #decoded_size = int(r2.cmd("ao~size[1]"))
    if x == 0:
        return 0, []

    ins = log_exec_r2_cmdj(f"aoj 1 @ {x}")
    if len(ins) == 0:
        return 0, []

    decoded_size = 0
    for op in ins:
        decoded_size += op["size"]

    return decoded_size, ins

#-----------------------------------------------------------------------
def SegStart(ea):
    # Just return the segment's start address
    try:
        return int(log_exec_r2_cmd("iS.~1[3]"), 16)
    except Exception:
        return 0

#-----------------------------------------------------------------------
def GetFunctionFlags(fcn):
    # TODO: Return if it looks like a function library, a thunk or a jump
    return -1 # FUNC_LIB

#-----------------------------------------------------------------------
def GuessType(ea):
    # It should return the guessed type of the current function.
    #
    # For example: for a strcpy like function, it should return a prototype
    # like:
    #
    # char __cdecl *strcpy(char *dst, const char *src);
    #
    # NOTE: It expects a semi-colon (;) at the end of the prototype.
    # NOTE 2: The calling convention is optional.
    return log_exec_r2_cmd(f"afcf @ {ea}")

#-----------------------------------------------------------------------
def GetFunctionCmt(ea, type):
    # Simply return the function's comment, if any
    return log_exec_r2_cmd("CCf")

#-----------------------------------------------------------------------
def GetType(ea):
    # Used to get the already set type of the specified function. It is a
    # bit different to GuessType. GuessType() guesses the type regardless
    # of it being set or not. GetType() just returns whatever type is set
    # to the function
    return log_exec_r2_cmd(f"afcf @ {ea}")

#-----------------------------------------------------------------------
def GetManyBytes(ea, size, use_dbg=False):
    # Return a buffer with the contents from 'ea' (address) to 'ea' + size.
    # The option argument 'use_dbg' is used to determine if the buffer is
    # read from the file or from memory (if using a debugger). That 3rd
    # optional parameter makes no sense in Diaphora.
    _bytes = log_exec_r2_cmdj("p8j %s @ %s" % (size, ea))
    return bytes(_bytes)

#-----------------------------------------------------------------------
def GetInputFileMD5():
    md5 = log_exec_r2_cmd("!rahash2 -qa md5 $R2_FILE").split(" ")[0]
    return md5

#-----------------------------------------------------------------------
def MinEA():
    addresses = []
    r2_cmd_output = log_exec_r2_cmd('iSq~[0]')
    r2_cmd_output = r2_cmd_output.splitlines()
    if len(r2_cmd_output) > 1:
        for i in range(0,len(r2_cmd_output)):
            addresses.append(int(r2_cmd_output[i],16))
        return min(addresses)
    else:
        ea = 0
        try:
            ea = int(log_exec_r2_cmd('iSq~[0]'), 16)
        except Exception:
            pass
        return ea

def MaxEA():
    # Return the maximum (read, last) address in the database.
    # For example, if the last segment in the program being analysed does
    # end at 0x401FFF, then, that's the maximum address.

    #get number of sections (use to index row in next command since -1
    #no longer works as an index)
    ea = 0
    try:
        n = int(log_exec_r2_cmd('iSq~?'))
        ea = int(log_exec_r2_cmd('iSq~:{}[1]'.format(n-1)), 16)
    except Exception:
        pass
    return ea

def GetMnem(x):
    return log_exec_r2_cmd('pi 1 @ %s'%(x)).split(' ')[0]

def GetDisasm(x):
    return log_exec_r2_cmd('pi 1 @ %s'%(x))

def ItemSize(x):
    return log_exec_r2_cmdj(f"aoj 1 @ {x}")[0].get("size", -1)

#-----------------------------------------------------------------------
def Functions(filter_lambda=None):
    fcns = log_exec_r2_cmdj("aflj")
    if not fcns:
        return []

    if filter_lambda:
        fcns = list(filter(filter_lambda, fcns))

    return [str(fcn["offset"]) for fcn in fcns]

#-----------------------------------------------------------------------
def Names():
    # Return a dictionary with {address: nameofthing}
    res = {}
    for flag in log_exec_r2_cmdj("fj"):
        res[flag["offset"]] = flag["name"]
    return res

#-----------------------------------------------------------------------
def r2_open(input_path, ident_libs = False):
    global r2
    r2 = r2pipe.open(f"ccall://{input_path}", flags=["-2", "-q"])
    r2.use_cache = True
    r2.cmd("aaaa")
    #r2.cmd("aac")

    # perform analysis
    r2.cmd("e asm.flags=false")
    r2.cmd("e asm.bytes=false")
    r2.cmd("e scr.color=false")
    r2.cmd("e io.cache=true")
    #r2.cmd("aeim")
    r2.cmd("e anal.hasnext=true")

    dll_extensions = {
        "Darwin": "dylib",
        "Linux": "so",
        "Windows": "dll"
    }

    # Workaround to load the Ghidra plugins because ccall is bugged 
    # and does not load it automatically
    ext = dll_extensions.get(platform.system())
    r2.cmd(f"L {os.path.expanduser('~/.local/share/radare2/plugins/core_ghidra.' + ext)}")
    if ident_libs:
        scan_libs()

def r2_close():
    global r2
    global _all_fns
    global _no_ret_fns
    r2.quit()
    r2 = None
    _all_fns = None
    _no_ret_fns = None

def get_r2():
    return r2

