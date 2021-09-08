import os
import time
import logging
from logging.handlers import RotatingFileHandler
import r2pipe

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

def get_function_name(ea):
    try:
        return log_exec_r2_cmdj(f"fd.j @ {ea}")[0]
    except Exception:
        return {}

def get_flag_at_addr(ea):
    return log_exec_r2_cmdj(f"fdj @ {ea}")

def is_func(ea):
    return bool(log_exec_r2_cmdj(f"fd.j @ {ea}"))

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
    res = []
    try:
        bbs = log_exec_r2_cmdj("afbj @ %s"%(addr))
    except Exception:
        log.error("NO BASIC BLOCKS FOR %s"%(addr))
        return res

    if not bbs:
        log.warn("EMPTY BB LIST FOR %s"%(addr))
        return res
    for bb in bbs:
        try:
            if +bb["jump"] == addr:
                res.push (+bb["addr"])
        except Exception:
            pass
        try:
            if +bb["fail"] == addr:
                res.push (+bb["addr"])
        except Exception:
            pass
    return res

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
    # TODO: Return a list of code references to address 'x'. The value 'y',
    # in IDA, is used to consider the previous instruction (y=1) as a valid
    # code reference or if it should be ignored (y=0).
    return map(int16, log_exec_r2_cmd('axtq.@ %s'%(x)).split('\n'))

def CodeRefsFrom(x, _):
    # ???
    return map(int16, log_exec_r2_cmd(f"axfq. @ {x}").split('\n'))

def DataRefsFrom(x):
    return log_exec_r2_cmdj(f"axfj @ {x}")

def GetOperandValue(x, y):
    # TODO XXX
    return 0

#-----------------------------------------------------------------------
def r2_get_imagebase():
    #ep = ((int(r2.cmd("ieq"), 16) >> 24) << 24)
    ep = int(log_exec_r2_cmd("ia~baddr[1]"), 16)
    log.debug("IMAGE BASE %s"%ep)
    return ep

#-----------------------------------------------------------------------
def r2_get_idp_name():
    # TODO: idaapi.get_idp_name() returns the current processor (CPU arch)
    # of the opened binary.
    return log_exec_r2_cmd('ij~{core.arch}')
    #return r2.cmd('e asm.arch')

#-----------------------------------------------------------------------
def GetStructIdByName(x):
    # Relevant to structs: get the internal id of a struct by its name.
    return None

#-----------------------------------------------------------------------
def decompile(ea):
    return log_exec_r2_cmd(f"pdg @ {ea}")

#-----------------------------------------------------------------------
def get_func(ea):
    # In IDA, it should return a "function object". Mostly specific to get
    # the start and end address, as well as the size, etc...
    fns = log_exec_r2_cmdj(f"afij @ {ea}")
    if fns and len(fns) > 0:
        return fns[0]
    else:
        return None

#-----------------------------------------------------------------------
def GetInstructionList():
    # TODO: Return a list of the total mnemonics supported by the current
    # disassembler. It's used to calculate the small-primes-product of the
    # function, by assigning a prime correspondent to the mnemonic in the
    # given list. Example:
    #
    # CPU_MY_ARCH = ["push", "pop", "call", "ret", "mov"]
    #
    # Given than example instruction set, push would be 2, pop 3, call 5,
    # ret 7 and mov 11. Then, for a function like this:
    #
    # push 1
    # pop  y
    # call x
    # ret
    #
    # ...it would calculate a SPP of 2*3*5*7 (210). If the instructions
    # are re-ordered, it will still give out the same "hash" value and,
    # also, if there are different instructions when comparing 2 functions
    # we can just remove all the common primes in the 2 sets and determine
    # which are the specific instructions that are different between them.
    #
    return []

#-----------------------------------------------------------------------
def Heads(startEA, endEA):
    # TODO: Return a list with all the instructions between 'startEA', the
    # start address, and 'endEA', the end address.
    res = log_exec_r2_cmd(f"pid {endEA - startEA} @ {startEA}~[0]")
    return map(int16, res.split("\n"))

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
    # TODO: It should return the guessed type of the current function.
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
    # TODO: Return the maximum (read, last) address in the database.
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
    return int(log_exec_r2_cmd('ao~size[1]'), 16)

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
    # TODO: Return a dictionary with {"name_of_thing":0xaddress}
    #
    # Example: {"main": 0x401000, "foo":0x4010200, "global_var": 0x402010}
    res = {}
    for flag in log_exec_r2_cmd("f").split("\n"):
        w = flag.split(" ")
        res[w[2]] = w[0]
    return res

#-----------------------------------------------------------------------
def r2_open(input_path):
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

    # Workaround to load the Ghidra plugins because ccall is bugged 
    # and does not load it automatically
    r2.cmd(f"L {os.path.expanduser('~/.local/share/radare2/plugins/core_ghidra.dylib')}")

def r2_close():
    global r2
    r2.quit()
    r2 = None

def get_r2():
    return r2
