#!/usr/bin/env python3
"""
Diaphora, a diffing plugin for Radare2
Copyright (c) 2021, Fernando Domínguez
Copyright (c) 2017, Sergi Alvarez

Based on IDA backend by:
Copyright (c) 2015-2017, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import re
import sys
import time
import json
import decimal
import difflib
import threading
import logging
from logging.handlers import RotatingFileHandler
from hashlib import md5, sha256

try:
    import thread
except ImportError:
    import _thread as thread

import r2diaphora
from r2diaphora import diaphora
from r2diaphora.others.tarjan_sort import strongly_connected_components, robust_topological_sort
from r2diaphora.jkutils.factor import primesbelow as primes
from r2diaphora.jkutils.graph_hashes import CKoretKaramitasHash

from r2diaphora.idaapi.idaapi_to_r2 import *

LOG_FORMAT = "%(asctime)-15s [%(levelname)s] - %(message)s"
log = logging.getLogger("diaphora.r2")
log.setLevel(logging.DEBUG)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter(LOG_FORMAT)
console.setFormatter(formatter)
log.addHandler(console)

if os.getenv("MODE") == "DEBUG":
    print("[*] Running in DEBUG mode")
    fh = RotatingFileHandler("diaphora_debug.log", maxBytes=1073741824, backupCount=5)      # 1GB
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter(LOG_FORMAT)
    fh.setFormatter(formatter)
    log.addHandler(fh)

# Messages
MSG_RELAXED_RATIO_ENABLED = """AUTOHIDE DATABASE\n<b>Relaxed ratio calculations</b> will be enabled. It will ignore many small
modifications to functions and will match more functions with higher ratios. Enable this option if you're only interested in the
new functionality. Disable it for patch diffing if you're interested in small modifications (like buffer sizes).
<br><br>
This is automatically done for diffing big databases (more than 20,000 functions in the database).<br><br>
You can disable it by un-checking the 'Relaxed calculations of differences ratios' option."""

MSG_FUNCTION_SUMMARIES_ONLY = """AUTOHIDE DATABASE\n<b>Do not export basic blocks or instructions</b> will be enabled.<br>
It will not export the information relative to basic blocks or<br>
instructions and 'Diff assembly in a graph' will not be available.
<br><br>
This is automatically done for exporting huge databases with<br>
more than 100,000 functions.<br><br>
You can disable it by un-checking the 'Do not export basic blocks<br>
or instructions' option."""


#-----------------------------------------------------------------------
def cdquit(fn_name):
    # print to stderr, unbuffered in Python 2.
    print('[-] Timeout: {0} took too long'.format(fn_name), file=sys.stderr)
    sys.stderr.flush() # Python 3 stderr is likely buffered.
    thread.interrupt_main() # raises KeyboardInterrupt

def timeout(s):
    '''
    use as decorator to exit process if 
    function takes longer than s seconds
    '''
    def outer(fn):
        def inner(*args, **kwargs):
            timer = threading.Timer(s, cdquit, args=[fn.__name__])
            timer.start()
            try:
                result = fn(*args, **kwargs)
            finally:
                timer.cancel()
            return result
        return inner
    return outer


#-----------------------------------------------------------------------
g_bindiff_opts = {
    "decompiler_command": "pdg",
    "use_decompiler": True
}

#-----------------------------------------------------------------------
class CIDABinDiff(diaphora.CBinDiff):
    def __init__(self, db_name: str = ""):
        diaphora.CBinDiff.__init__(self, db_name)
        self.names = Names()
        self.min_ea = MinEA()
        self.max_ea = MaxEA()

    def show_choosers(self, force=False):
        if len(self.best_chooser.items) > 0:
            self.best_chooser.show(force)

        if len(self.partial_chooser.items) > 0:
            self.partial_chooser.show(force)

        if self.unreliable_chooser is not None and len(self.unreliable_chooser.items) > 0:
            self.unreliable_chooser.show(force)
        if self.unmatched_primary is not None and len(self.unmatched_primary.items) > 0:
            self.unmatched_primary.show(force)
        if self.unmatched_second is not None and len(self.unmatched_second.items) > 0:
            self.unmatched_second.show(force)

    def do_export(self, function_filter = None, userdata = ""):
        callgraph_primes = 1
        callgraph_all_primes = {}
        func_list = Functions(function_filter)
        total_funcs = len(func_list)
        t = time.time()

        self.db.commit()
        self.db.start_transaction()

        log.debug("FUNC LISTING IS %s" % (func_list))
        i = 0
        for func in func_list:
            log.debug("PROPS FOR FUNC cur %s" % (func))
            props = self.read_function(func)
            if not props:
                i += 1
                continue

            ret = props[11]
            name = props[0]
            callgraph_primes *= decimal.Decimal(ret)
            try:
                callgraph_all_primes[ret] += 1
            except KeyError:
                callgraph_all_primes[ret] = 1

            props = list(props)
            props[42] = userdata
            try:
                self.save_function(props)
            except Exception:
                log.exception(f"Failed to save function {func}")
                i += 1
                continue

            i += 1
            line = "Exported %s fn (%d/%d). Elapsed %d s, remaining time ~%d s"
            elapsed = time.time() - t
            remaining = (elapsed / i) * (total_funcs - i)
            log.info(line % (name, i, total_funcs, elapsed, remaining))

        # Try to fix bug #30 and, also, try to speed up operations as
        # doing a commit every 10 functions, as before, is overkill.
        if total_funcs > 1000 and i % (total_funcs/1000) == 0:
            self.db.commit()
            self.db.start_transaction()

        md5sum = GetInputFileMD5()
        self.save_callgraph(str(callgraph_primes), json.dumps(callgraph_all_primes), md5sum)
        self.export_structures()
        self.export_til()

    def export(self, function_filter = None, userdata = ""):
        try:
            self.do_export(function_filter, userdata)
        except Exception:
            log.exception("")

        self.db.commit()
        self.db_close()

    def reinit(self, main_db, diff_db, create_choosers=True):
        log.debug("Main database '%s'." % main_db)
        log.debug("Diff database '%s'." % diff_db)

        self.__init__(main_db)
        self.attach_database(diff_db)

        if create_choosers:
            self.create_choosers()

    def import_definitions_only(self, filename):
        self.reinit(":memory:", filename)
        self.import_til()
        self.import_definitions()

    def import_one(self, item):
        # Import all the type libraries from the diff database
        self.import_til()
        # Import all the struct and enum definitions
        self.import_definitions()

        # Import just the selected item
        ea1 = str(int(item[1], 16))
        ea2 = str(int(item[3], 16))
        self.do_import_one(ea1, ea2, True)

        new_func = self.read_function(str(ea1))
        self.delete_function(ea1)
        self.save_function(new_func)

        self.db.commit()

    def import_instruction_level(self, ea1, ea2, cur):
        cur = self.db_cursor()
        try:
            # Check first if we have any importable items
            sql = """ select ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.name name, ins.type type
                                    from diff.function_bblocks bb,
                                             diff.functions f,
                                             diff.bb_instructions bbi,
                                             diff.instructions ins
                                 where f.id = bb.function_id
                                     and bbi.basic_block_id = bb.basic_block_id
                                     and ins.id = bbi.instruction_id
                                     and f.address = ?
                                     and (ins.comment1 is not null
                                         or ins.comment2 is not null
                                         or ins.name is not null) """
            cur.execute(sql, (ea2,))
            import_rows = cur.fetchall()
            if len(import_rows) > 0:
                import_syms = {}
                for row in import_rows:
                    import_syms[row["dis"]] = [row["ea"], row["cmt1"], row["cmt2"], row["name"], row["type"]]

                # Check in the current database
                sql = """ select ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, ins.name name, ins.type type
                                        from function_bblocks bb,
                                                 functions f,
                                                 bb_instructions bbi,
                                                 instructions ins
                                     where f.id = bb.function_id
                                         and bbi.basic_block_id = bb.basic_block_id
                                         and ins.id = bbi.instruction_id
                                         and f.address = ?"""
                cur.execute(sql, (str(ea1),))
                match_rows = cur.fetchall()
                if len(match_rows) > 0:
                    matched_syms = {}
                    for row in match_rows:
                        matched_syms[row["dis"]] = [row["ea"], row["cmt1"], row["cmt2"], row["name"], row["type"]]

                    # We have 'something' to import, let's diff the assembly...
                    sql = """select *
                                         from (
                                     select assembly, 1
                                         from functions
                                        where address = ?
                                            and assembly is not null
                         union select assembly, 2
                                         from diff.functions
                                        where address = ?
                                            and assembly is not null)
                                        order by 2 asc"""
                    cur.execute(sql, (ea1, ea2))
                    diff_rows = cur.fetchall()
                    if len(diff_rows) > 0:
                        lines1 = diff_rows[0]["assembly"]
                        lines2 = diff_rows[1]["assembly"]

                        matches = {}
                        to_line = None
                        change_line = None
                        diff_list = difflib.ndiff(lines1.splitlines(1), lines2.splitlines(1))
                        for x in diff_list:
                            if x[0] == '-':
                                change_line = x[1:].strip(" ").strip("\r").strip("\n")
                            elif x[0] == '+':
                                to_line = x[1:].strip(" ").strip("\r").strip("\n")
                            elif change_line is not None:
                                change_line = None

                            if to_line is not None and change_line is not None:
                                matches[change_line] = to_line
                                if change_line in matched_syms and to_line in import_syms:
                                    self.import_instruction(matched_syms[change_line], import_syms[to_line])
                                change_line = to_line = None
        finally:
            cur.close()

    def clean_pseudocode(self, code):
        lines = code.split("\n")
        code = [line for line in lines if not line.strip().startswith("//")]
        code = "\n".join(code)

        code = re.sub(r"__regparm\d", "", code)

        return code.replace("sym.imp.", "")\
                   .replace("sym.", "")\
                   .replace("fcn.", "fcn_")\
                   .replace("flirt.", "")\
                   .replace("obj.", "")\
                   .replace("noreturn", "")

    def decompile_and_get(self, ea):
        sv = decompile(ea, decompiler_command=self.decompiler_command);
        if sv is None:
            # Failed to decompile
            return None

        visitor = CAstVisitor()
        visitor.apply_to(
            f"""
            {self.clean_pseudocode(sv)}
            """
        )
        self.pseudo_hash[ea] = visitor.primes_hash
        self.pseudo[ea] = []

        first_line = None
        for line in sv.split("\n"):
            if line == "" or line.startswith("//"):
                continue

            if first_line is None:
                first_line = line
            else:
                self.pseudo[ea].append(line)
        return first_line

    def guess_type(self, ea):
        t = GuessType(ea)
        if self.use_decompiler_always:
            try:
                ret = self.decompile_and_get(ea)
                if ret:
                    t = ret
            except Exception:
                log.warning("Cannot decompile 0x%x: %s" % (ea, str(sys.exc_info()[1])))
        return t

    # Ripped out from REgoogle
    def constant_filter(self, value):
        """Filter for certain constants/immediate values. Not all values should be
        taken into account for searching. Especially not very small values that
        may just contain the stack frame size.

        @param value: constant value
        @type value: int
        @return: C{True} if value should be included in query. C{False} otherwise
        """
        # no small values
        if value < 0x10000:
            return False

        if value & 0xFFFFFF00 == 0xFFFFFF00 or value & 0xFFFF00 == 0xFFFF00 or \
             value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00 or \
             value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00:
            return False

        #no single bits sets - mostly defines / flags
        for i in range(64):
            if value == (1 << i):
                return False

        return True

    def is_constant(self, oper, ea):
        value = oper["value"]
        # make sure, its not a reference but really constant
        drefs = [d.get("to", -1) for d in DataRefsFrom(ea)]
        if value in drefs:
            return False

        return True

    # Most important function
    @timeout(300)
    def read_function(self, f, discard=False):
        log.debug(f"READ F {f}")

        name = ""
        true_name = ""
        try:
            name_info = log_exec_r2_cmdj(f"fd.j @ {f}")[0]
            name = name_info.get("name")
            true_name = name_info.get("realname")
            log.debug(f"F NAME {name}")
            demangled_name = name #r2.cmdj(f"isj. @ {f}").get("name", "")
            #if demangled_name != "":
            #    name = demangled_name
            if name.startswith("section..") or name.startswith("sym.imp."):
                log.info(f"Skipping uninteresting function {name}")
                return False

        except Exception:
            log.exception(f"Could not read function name for address {f}")

        # WTF
        f = int(f)

        fninfo = get_func(f)
        flow = log_exec_r2_cmdj(f"afbj @ {f}")
        size = fninfo.get("size", 0)

        # TODO Already recognized runtime's function?
        #flags = GetFunctionFlags(f)
        #if flags & FUNC_LIB or flags == -1:
        #    return False

        #if self.exclude_library_thunk:
            # Skip library and thunk functions
        #    flags = GetFunctionFlags(f)
        #    if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
        #        return False

        nodes = 0
        edges = 0
        instructions = 0
        mnems = []
        dones = {}
        names = set()
        bytes_hash = []
        bytes_sum = 0
        function_hash = []
        outdegree = 0
        indegree = len(list(CodeRefsTo(f, 1)))
        assembly = {}
        basic_blocks_data = {}
        bb_relations = {}
        bb_topo_num = {}
        bb_topological = {}
        switches = []
        bb_degree = {}
        bb_edges = []
        assembly_addrs = [] # TODO: Fill info
        kgh_hash = ""
        callers = [c.get("from") for c in log_exec_r2_cmdj(f"axtj @ {f}")]
        fn_refs = log_exec_r2_cmdj(f"axffj @ {f}")
        callees = [c.get("at") for c in fn_refs if c.get("type") == "CALL"]

        # Intialize to string constants, inmediate constants will be added later
        constants = [
            GetString(r.get("ref"), -1, -1) for r in fn_refs 
                        if r.get("type") == "DATA" and r.get("name", "").startswith("str.")
        ]

        mnemonics_spp = 1
        cpu_ins_list = GetInstructionList()
        cpu_ins_list.sort()

        image_base = self.get_base_address()
        flags = log_exec_r2_cmdj("fj")
        s = time.time()
        log.debug(f"Fn {name} - Starting block iteration")
        for block in flow:
            nodes += 1
            block_startEA = +block["addr"];
            block_endEA = +block["addr"] + +block["size"];
            block.update({"startEA": block_startEA})
            block.update({"endEA": block_endEA})
            instructions_data = []

            block_ea = block_startEA - image_base
            idx = len(bb_topological)
            bb_topological[idx] = []
            bb_topo_num[block_ea] = idx

            for x in Heads(block["addr"], block["ninstr"]):
                mnem = GetMnem(x)
                disasm = GetDisasm(x)
                instructions += 1

                if mnem in cpu_ins_list:
                    mnemonics_spp *= self.primes[cpu_ins_list.index(mnem)]

                try:
                    assembly[block_ea].append(disasm)
                except KeyError:
                    if nodes == 1:
                        assembly[block_ea] = [disasm]
                    else:
                        try:
                            assembly[block_ea] = ["loc_%x:" % x, disasm]
                        except Exception:
                            assembly[block_ea] = ["loc_%s:" % x, disasm]

                decoded_size, ins = diaphora_decode(x)
                if len(ins) < 1:
                    continue
                ins = ins[0]

                for oper in ins.get("opex", {}).get("operands", []):
                    if oper["type"] == "imm":
                        if self.is_constant(oper, x) and self.constant_filter(oper["value"]):
                            constants.append(oper["value"])

                mnem_bytes = ins["bytes"][0:ins["mask"].rfind("f") + 1]
                curr_bytes = bytes.fromhex(mnem_bytes)

                bytes_hash.append(curr_bytes)
                bytes_sum += sum(curr_bytes)

                function_hash.append(bytes.fromhex(ins["bytes"]))
                outdegree += len(CodeRefsFrom(x, 0))
                mnems.append(mnem)
                op_value = GetOperandValue(x, 1)
                if op_value == -1:
                    op_value = GetOperandValue(x, 0)

                tmp_name = None
                if op_value != BADADDR and op_value in self.names:
                    tmp_name = self.names[op_value]
                    if not tmp_name.startswith("fcn."):
                        names.add(tmp_name)

                l = list(CodeRefsFrom(x, 0))
                if len(l) == 0:
                    l = DataRefsFrom(x)

                tmp_type = None
                for ref in l:
                    if ref in self.names:
                        tmp_name = self.names[ref]
                        tmp_type = GetType(ref)

                ins_cmt1 = GetCommentEx(x, 0)
                ins_cmt2 = GetCommentEx(x, 1)
                instructions_data.append([x - image_base, mnem, disasm, ins_cmt1, ins_cmt2, tmp_name, tmp_type])

            basic_blocks_data[block_ea] = instructions_data
            bb_relations[block_ea] = []
            if block_ea not in bb_degree:
                # bb in degree, out degree
                bb_degree[block_ea] = [0, 0]

            succs = block_succs(block_startEA)
            preds = block_preds(block_startEA)
            for succ_block in succs:
                succ_base = succ_block - image_base #.startEA - image_base
                bb_relations[block_ea].append(succ_base)
                bb_degree[block_ea][1] += 1
                bb_edges.append((block_ea, succ_base))
                if succ_base not in bb_degree:
                    bb_degree[succ_base] = [0, 0]
                bb_degree[succ_base][0] += 1

                edges += 1
                indegree += 1
                if succ_block not in dones:
                    dones[succ_block] = 1

            for pred_block in preds:
                try:
                    bb_relations[pred_block - image_base].append(block["startEA"] - image_base)
                except KeyError:
                    bb_relations[pred_block - image_base] = [block["startEA"] - image_base]

                edges += 1
                outdegree += 1
                #if not dones.has_key(succ_block):
                #    dones[succ_block] = 1
                if pred_block not in dones:
                    dones[pred_block] = 1

        log.debug(f"Fn {name} - Block iteration: {time.time() - s}s")

        sws = [f for f in flags if f["name"].startswith("switch.")]
        for sw in sws:
            # Flags have an offset value, but this value is not the same for 
            # switch flags and their cases
            sw_ref = sw["name"].split(".")[1].lstrip("0x").lstrip("0")
            if not test_addr_within_function(f, sw["offset"]):
                continue

            cases = [f for f in flags if f["name"].startswith(f"case.0x{sw_ref}.")]
            cases_values = [case["name"].split(".")[-1] for case in cases]
            switches.append([len(cases), cases_values])

        for block in flow:
            block_ea = block["addr"] - image_base
            for succ_block in block_succs(block["addr"]):
                succ_base = succ_block - image_base
                try:
                    bb_topological[bb_topo_num[block_ea]].append(bb_topo_num[succ_base])
                except KeyError:
                    # tailcall functions will generate a KeyError as jump'ed BB is not
                    # on function topology, but that's perfectly fine
                    pass

        s = time.time()
        strongly_connected_spp = 0
        try:
            strongly_connected = strongly_connected_components(bb_relations)
            bb_topological_sorted = robust_topological_sort(bb_topological)
            bb_topological = json.dumps(bb_topological_sorted)
            strongly_connected_spp = 1
            for item in strongly_connected:
                val = len(item)
                if val > 1:
                    strongly_connected_spp *= self.primes[val]
        except Exception:
            # XXX: FIXME: The original implementation that we're using is
            # recursive and can fail. We really need to create our own non
            # recursive version.
            strongly_connected = []
            bb_topological = None

        loops = 0
        for sc in strongly_connected:
            if len(sc) > 1:
                loops += 1
            else:
                if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
                    loops += 1

        asm = []
        keys = list(assembly.keys())
        keys.sort()

        # After sorting our the addresses of basic blocks, be sure that the
        # very first address is always the entry point, no matter at what
        # address it is.
        try:
            keys.remove(f - image_base)
        except Exception:
            pass
        keys.insert(0, f - image_base)
        for key in keys:
            try:
                asm.extend(assembly[key])
            except Exception:
                log.exception("")
                pass
        asm = "\n".join(asm)
        log.debug(f"Fn {name} - Topological analysis: {time.time() - s}s")

        cc = edges - nodes + 2
        proto = self.guess_type(f)
        proto2 = GetType(f)
        try:
            prime = str(self.primes[cc])
        except Exception:
            log.error("Cyclomatic complexity too big: 0x%x -> %d" % (f, cc))
            prime = 0

        comment = GetFunctionCmt(f, 1)
        bytes_hash = md5(b"".join(bytes_hash)).hexdigest()
        function_hash = md5(b"".join(function_hash)).hexdigest()

        function_flags = GetFunctionFlags(f)
        pseudo = None
        pseudo_hash1 = None
        pseudo_hash2 = None
        pseudo_hash3 = None
        pseudo_lines = 0
        pseudocode_primes = None
        if f in self.pseudo:
            pseudo = "\n".join(self.pseudo[f])
            pseudo_lines = len(self.pseudo[f])
            pseudo_hash1, pseudo_hash2, pseudo_hash3 = self.kfh.hash_bytes(pseudo).split(";")
            if pseudo_hash1 == "":
                pseudo_hash1 = None
            if pseudo_hash2 == "":
                pseudo_hash2 = None
            if pseudo_hash3 == "":
                pseudo_hash3 = None
            pseudocode_primes = str(self.pseudo_hash[f])

        try:
            clean_assembly = self.get_cmp_asm_lines(asm)
        except Exception:
            clean_assembly = ""
            log.error("Error getting assembly for 0x%x" % f)

        clean_pseudo = self.get_cmp_pseudo_lines(pseudo)

        md_index = 0
        if bb_topological:
            bb_topo_order = {}
            for i, scc in enumerate(bb_topological_sorted):
                for bb in scc:
                    bb_topo_order[bb] = i
            tuples = []
            for src, dst in bb_edges:
                tuples.append((
                        bb_topo_order[bb_topo_num[src]],
                        bb_degree[src][0],
                        bb_degree[src][1],
                        bb_degree[dst][0],
                        bb_degree[dst][1],))
            rt2, rt3, rt5, rt7 = (decimal.Decimal(p).sqrt() for p in (2, 3, 5, 7))
            emb_tuples = (sum((z0, z1 * rt2, z2 * rt3, z3 * rt5, z4 * rt7))
                            for z0, z1, z2, z3, z4 in tuples)
            md_index = sum((1 / emb_t.sqrt() for emb_t in emb_tuples))
            md_index = str(md_index)

        x = f
        seg_rva = x - SegStart(x)
        rva = f - self.get_base_address()
        log.debug(f"Fn {name} - Decompiler: {time.time() - s}s")

        kgh = CKoretKaramitasHash(get_r2())
        kgh_hash = kgh.calculate(f)

        return (name, nodes, edges, indegree, outdegree, size, instructions, mnems, names,
                         proto, cc, prime, f, comment, true_name, bytes_hash, pseudo, pseudo_lines,
                         pseudo_hash1, pseudocode_primes, function_flags, asm, proto2,
                         pseudo_hash2, pseudo_hash3, len(strongly_connected), loops, rva, bb_topological,
                         strongly_connected_spp, clean_assembly, clean_pseudo, mnemonics_spp, switches,
                         function_hash, bytes_sum, md_index, constants, len(constants), seg_rva,
                         assembly_addrs, kgh_hash, None,
                         callers, callees,
                         basic_blocks_data, bb_relations)

    def create_function_dictionary(self, l):
        (name, nodes, edges, indegree, outdegree, size, instructions, mnems, names,
        proto, cc, prime, f, comment, true_name, bytes_hash, pseudo, pseudo_lines,
        pseudo_hash1, pseudocode_primes, function_flags, asm, proto2,
        pseudo_hash2, pseudo_hash3, strongly_connected_size, loops, rva, bb_topological,
        strongly_connected_spp, clean_assembly, clean_pseudo, mnemonics_spp, switches,
        function_hash, bytes_sum, md_index, constants, constants_size, seg_rva,
        assembly_addrs, kgh_hash, userdata, callers, callees, basic_blocks_data,
        bb_relations) = l
        d = dict(
                name = name,
                nodes = nodes,
                edges = edges,
                indegree = indegree,
                outdegree = outdegree,
                size = size,
                instructions = instructions,
                mnems = mnems,
                names = names,
                proto = proto,
                cc = cc,
                prime = prime,
                f = f,
                comment = comment,
                true_name = true_name,
                bytes_hash = bytes_hash,
                pseudo = pseudo,
                pseudo_lines = pseudo_lines,
                pseudo_hash1 = pseudo_hash1,
                pseudocode_primes = pseudocode_primes,
                function_flags = function_flags,
                asm = asm,
                proto2 = proto2,
                pseudo_hash2 = pseudo_hash2,
                pseudo_hash3 = pseudo_hash3,
                strongly_connected_size = strongly_connected_size,
                loops = loops,
                rva = rva,
                bb_topological = bb_topological,
                strongly_connected_spp = strongly_connected_spp,
                clean_assembly = clean_assembly,
                clean_pseudo = clean_pseudo,
                mnemonics_spp = mnemonics_spp,
                switches = switches,
                function_hash = function_hash,
                bytes_sum = bytes_sum,
                md_index = md_index,
                constants = constants,
                constants_size = constants_size,
                seg_rva = seg_rva,
                assembly_addrs = assembly_addrs,
                kgh_hash = kgh_hash,
                callers = callers,
                callees = callees,
                basic_blocks_data = basic_blocks_data,
                bb_relations = bb_relations,
                userdata = userdata)
        return d

    def get_base_address(self):
        return r2_get_imagebase()

    def save_callgraph(self, primes, all_primes, md5sum):
        cur = self.db_cursor()
        sql = f"insert into `{self.db_name}`.program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (%s, %s, %s, %s)"
        proc = r2_get_idp_name()
        if BADADDR == 0xFFFFFFFFFFFFFFFF:
            proc += "64"
        cur.execute(sql, (primes, all_primes, proc, md5sum))
        cur.close()

    def GetLocalType(self, ordinal, flags):
        ret = GetLocalTinfo(ordinal)
        if ret is not None:
            (stype, fields) = ret
            if stype:
                name = GetLocalTypeName(ordinal)
                return idc_print_type(stype, fields, name, flags)
        return ""

    def export_structures(self):
        # It seems that GetMaxLocalType, sometimes, can return negative
        # numbers, according to one beta-tester. My guess is that it's a bug
        # in IDA. However, as we cannot reproduce, at least handle this
        # condition.
        local_types = GetMaxLocalType()
        if (local_types & 0x80000000) != 0:
            log.warning("GetMaxLocalType returned a negative number (0x%x)!" % local_types)
            return

        # XXX this is not working
        for i in range(local_types):
            name = GetLocalTypeName(i+1)
            definition = "" # self.GetLocalType(i+1, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI | PRTYPE_PRAGMA)
            type_name = "struct"
            if definition.startswith("enum"):
                type_name = "enum"
            elif definition.startswith("union"):
                type_name = "union"

            # For some reason, IDA my return types with the form "__int128 unsigned",
            # we want it the right way "unsigned __int128".
            if name and name.find(" ") > -1:
                names = name.split(" ")
                name = names[0]
                if names[1] == "unsigned":
                    name = "unsigned %s" % name

            self.add_program_data(type_name, name, definition)

    def get_til_names(self):
        idb_path = "" # GetIdbPath()
        filename, ext = os.path.splitext(idb_path)
        til_path = "%s.til" % filename

        return None
        with open(til_path, "rb") as f:
            line = f.readline()
            pos = line.find("Local type definitions")
            if pos > -1:
                tmp = line[pos+len("Local type definitions")+1:]
                pos = tmp.find("\x00")
                if pos > -1:
                    defs = tmp[:pos].split(",")
                    return defs
        return None

    def export_til(self):
        til_names = self.get_til_names()
        if til_names is not None:
            for til in til_names:
                self.add_program_data("til", til, None)

    def re_diff(self):
        self.best_chooser.Close()
        self.partial_chooser.Close()
        if self.unreliable_chooser is not None:
            self.unreliable_chooser.Close()
        if self.unmatched_primary is not None:
            self.unmatched_primary.Close()
        if self.unmatched_second is not None:
            self.unmatched_second.Close()

        self.matched1 = set()
        self.matched2 = set()

        self.diff(self.last_diff_db)

    def equal_db(self):
        are_equal = diaphora.CBinDiff.equal_db(self)
        if are_equal:
            self.do_continue = False
        return are_equal

#-----------------------------------------------------------------------
def _diff_or_export(function_filter = None, dbname = None, userdata = "", **options):
    global g_bindiff_opts

    total_functions = len(list(Functions(function_filter)))
    options["function_filter"] = function_filter
    opts = BinDiffOptions(**options)
    if dbname:
        opts.file_out = dbname
    bd = None

    try:
        bd = CIDABinDiff(opts.file_out)
        bd.use_decompiler_always = (get_arch() != "sh") and g_bindiff_opts.get("use_decompiler", True)
        bd.decompiler_command = g_bindiff_opts.get("decompiler_command", "pdg")
        bd.exclude_library_thunk = opts.exclude_library_thunk
        bd.unreliable = opts.unreliable
        bd.slow_heuristics = opts.slow
        bd.relaxed_ratio = opts.relax
        bd.experimental = opts.experimental
        bd.min_ea = opts.min_ea
        bd.max_ea = opts.max_ea
        bd.ida_subs = opts.ida_subs
        bd.ignore_sub_names = opts.ignore_sub_names
        bd.ignore_all_names = opts.ignore_all_names
        bd.ignore_small_functions = opts.ignore_small_functions
        bd.function_summaries_only = opts.func_summaries_only
        bd.max_processed_rows = diaphora.MAX_PROCESSED_ROWS * max(total_functions / 20000, 1)
        bd.timeout = diaphora.TIMEOUT_LIMIT * max(total_functions / 20000, 1)
        bd.open_db()
        bd.export(function_filter, userdata)
        log.info(f"Database exported: {opts.file_out}")

    except Exception:
        log.exception(f"Exception while exporting DB {opts.file_out}")

    return bd

#-----------------------------------------------------------------------
class BinDiffOptions:
    def __init__(self, **kwargs):
        total_functions = len(list(Functions(kwargs.get('function_filter', None))))
        self.file_in = kwargs.get('file_in', '')
        self.file_out = kwargs.get('file_out', '')
        self.use_decompiler = kwargs.get('use_decompiler', True)
        self.exclude_library_thunk = kwargs.get('exclude_library_thunk', True)
        # Enable, by default, relaxed calculations on difference ratios for
        # 'big' databases (>20k functions)
        self.relax = kwargs.get('relax', total_functions > 20000)
        if self.relax:
            log.debug(MSG_RELAXED_RATIO_ENABLED)
        self.unreliable = kwargs.get('unreliable', False)
        self.slow = kwargs.get('slow', False)
        self.experimental = kwargs.get('experimental', False)
        self.min_ea = 0 # kwargs.get('min_ea', MinEA())
        self.max_ea = -1 #kwargs.get('max_ea', MaxEA())
        self.ida_subs = kwargs.get('ida_subs', True)
        self.ignore_sub_names = kwargs.get('ignore_sub_names', True)
        self.ignore_all_names = kwargs.get('ignore_all_names', False)
        self.ignore_small_functions = kwargs.get('ignore_small_functions', False)
        # Enable, by default, exporting only function summaries for huge dbs.
        self.func_summaries_only = kwargs.get('func_summaries_only', total_functions > 100000)

#-----------------------------------------------------------------------
def is_r2_file(filename):
    fn = filename.lower()
    return fn.endswith(".r2")

#-----------------------------------------------------------------------
def is_ida_file(filename):
    fn = filename.lower()
    return fn.endswith(".idb") or fn.endswith(".i64") or \
            fn.endswith(".til") or fn.endswith(".id0") or \
            fn.endswith(".id1") or fn.endswith(".nam")

#-----------------------------------------------------------------------
def remove_file(filename):
    print("Remove file %s" % (filename))

#-----------------------------------------------------------------------

def _gen_diaphora_db(
        input_path: str,
        out_db: str,
        function_filter = None,
        userdata = ""
    ):
    global r2
    if not r2:
        r2_open(input_path)

    scan_libs()
    _diff_or_export(function_filter, dbname=out_db, userdata=userdata)
    if r2:
        r2_close()

def dbname_for_file(filepath):
    hash = ""
    with open(filepath, "rb") as f:
        d = f.read()
        hash = sha256(d).hexdigest();
    return hash

def generate_db_for_file(filepath, override_if_existing = False, function_filter = None):
    dbname = dbname_for_file(filepath)
    if diaphora.db_exists(dbname) and override_if_existing:
        log.info(f"Dropping database {dbname} as it was specified to override it")
        diaphora.drop_db(dbname)
    
    if not diaphora.db_exists(dbname):
        log.info(f"Generating database {dbname} for file {filepath}")
        _gen_diaphora_db(filepath, dbname, function_filter=function_filter)

def compare_dbs(db1name, db2name):
    bd = diaphora.CBinDiff(db1name)
    bd.open_db()
    bd.diff(db2name)
    return bd.get_results()

def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "file1",
        nargs=1,
        help='File to analyze'
    )
    parser.add_argument(
        "file2",
        nargs="?",
        default=None,
        help='(Optional) File to diff against'
    )
    parser.add_argument(
        "-f",
        dest='force_db_override',
        action='store_true',
        help='Force DB override'
    )

    parser.add_argument(
        "-nbbs",
        default=0,
        type=int,
        help='Functions with a number of basic blocks below this number are excluded from analysis'
    )

    parser.add_argument(
        "-o",
        default=None,
        help="Diff output file (HTML) - Default value: <db1name>_vs_<db2name>.html"
    )

    parser.add_argument(
        "-d",
        "--decompiler",
        default="ghidra",
        choices=["pdc", "ghidra"],
        help="Which decompiler to use"
    )

    parser.add_argument(
        "-nd",
        "--no-decompiler",
        dest='no_decompiler',
        action='store_true',
        help="Do not use the decompiler"
    )

    parser.add_argument(
        "-a",
        dest='analyze_all',
        action='store_true',
        help="Analyze ALL functions (by default library functions are skipped)"
    )

    args = parser.parse_args()
    args.file1 = args.file1[0]
    decompiler_commands = {
        "ghidra": "pdg",
        "pdc": "pdc"
    }

    g_bindiff_opts["decompiler_command"] = decompiler_commands.get(args.decompiler)
    g_bindiff_opts["use_decompiler"] = not args.no_decompiler

    db1name = dbname_for_file(args.file1)
    bd = diaphora.CBinDiff(db1name)

    fn_filter = lambda fn: (
        not fn["name"].startswith("flirt.") and fn["nbbs"] >= args.nbbs
    )
    if args.analyze_all:
        fn_filter = None

    generate_db_for_file(
        args.file1,
        override_if_existing=args.force_db_override,
        function_filter=fn_filter
    )

    if args.file2:
        db2name = dbname_for_file(args.file2)
        generate_db_for_file(
            args.file2,
            override_if_existing=args.force_db_override,
            function_filter=fn_filter
        )

        bd.open_db()
        bd.diff(db2name)
        matches = bd.get_results()
        output_name = None
        if args.o:
            output_name = args.o
        else:
            output_name = f"{db1name[0:10]}_vs_{db2name[0:10]}.html"
        r2diaphora.HtmlResults(matches, file1=args.file1, file2=args.file2).render(output_name)
        print(f"[+] Diff saved to {output_name}")

if __name__ == "__main__":
    main()