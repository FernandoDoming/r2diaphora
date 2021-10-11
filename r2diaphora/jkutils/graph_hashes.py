#!/usr/bin/python

"""
Yet another Control Flow Graph hash using small-primes-product.
An implementation of the Koret-Karamitas (KOKA) CFGs hashing algorithm.

Based on the paper Efficient Features for Function Matching between Binary
Executables by Huku (Chariton Karamitas, CENSUS S.A., huku@census-labs.com).

Copyright (c) 2018-2019, Joxean Koret
"""



import sys
import time
import logging

from r2diaphora.idaapi.idaapi_to_r2 import *

try:
  from r2diaphora.others.tarjan_sort import strongly_connected_components
except ImportError:
  from r2diaphora.tarjan_sort import strongly_connected_components

log = logging.getLogger("diaphora.graph_hashes")

#-------------------------------------------------------------------------------
# Different type of basic blocks (graph nodes).
NODE_ENTRY = 2
NODE_EXIT = 3
NODE_NORMAL = 5

#
# NOTE: In the current implementation (Nov-2018) all edges are considered as if
# they were conditional. Keep reading...
#
EDGE_IN_CONDITIONAL = 7
EDGE_OUT_CONDITIONAL = 11

#
# Reserved but unused because, probably, it doesn't make sense when comparing
# multiple different architectures.
#
#EDGE_IN_UNCONDITIONAL = 13
#EDGE_OUT_UNCONDITIONAL = 17

# 
# The following are feature types that aren't applied at basic block but rather
# at function level. The idea is that if we do at function level we will have no
# problems finding the same function that was re-ordered because of some crazy
# code a different compiler decided to create (i.e., resilient to reordering).
#
FEATURE_LOOP = 19
FEATURE_CALL = 23
FEATURE_DATA_REFS = 29
FEATURE_CALL_REF = 31
FEATURE_STRONGLY_CONNECTED = 37
FEATURE_FUNC_NO_RET = 41
FEATURE_FUNC_LIB = 43
FEATURE_FUNC_THUNK = 47

#-------------------------------------------------------------------------------
# Implementation of the KOKA (Koret-Karamitas) hashing algorithm for IDA
class CKoretKaramitasHash:
  def __init__(self, r2):
    self.r2 = r2

  #-------------------------------------------------------------------------------
  def log_exec_r2_cmdj(self, cmd):
    s = time.time()
    r = self.r2.cmdj(cmd)
    log.debug(f"R2 CMDJ: {cmd}: {time.time() - s}s")
    return r

  def log_exec_r2_cmd(self, cmd):
    s = time.time()
    r = self.r2.cmd(cmd)
    log.debug(f"R2 CMD: {cmd}: {time.time() - s}s")
    return r

  #-------------------------------------------------------------------------------
  def get_node_value(self, succs, preds):
    """ Return a set of prime numbers corresponding to the characteristics of the node. """
    ret = 1
    if preds == 0:
      ret *= NODE_ENTRY
    
    if succs == 0:
      ret *= NODE_EXIT

    ret *= NODE_NORMAL
    return ret

  def get_edges_value(self, bb, succs, preds):
    ret = 1
    for _ in succs:
      ret *= EDGE_OUT_CONDITIONAL

    for _ in preds:
      ret *= EDGE_IN_CONDITIONAL

    return ret

  def is_call_insn(self, ea):
    _, inss = diaphora_decode(ea)
    if len(inss) < 1:
      return False
    return "call" in inss[0].get("type")

  def calculate(self, f):
    fname = get_function_name(f).get("name")
    if not fname:
      return "NO-FUNCTION"

    flow = self.log_exec_r2_cmdj(f"afbj @ {f}")
    if flow is None:
      return "NO-FLOW-GRAPH"

    hash = 1

    # Variables required for calculations of previous ones
    bb_relations = {}

    # Iterate through each basic block
    for block in flow:
      block_ea = +block['addr'];
      block_end_ea = +block['addr'] + +block['size'];
      block.update({"start_ea": block_ea})
      block.update({"end_ea": block_end_ea})

      if block["end_ea"] == 0:
        continue

      succs = block_succs(block_ea)
      preds = block_preds(block_ea)

      hash *= self.get_node_value(len(succs), len(preds))
      hash *= self.get_edges_value(block, succs, preds)

      # ...and each instruction on each basic block
      for ea in Heads(block["start_ea"], block["ninstr"]):

        if self.is_call_insn(ea):
          hash *= FEATURE_CALL

        l = list(DataRefsFrom(ea))
        if len(l) > 0:
          hash *= FEATURE_DATA_REFS

        for xref in CodeRefsFrom(ea, 0):
          if not is_func(xref) or get_flag_at_addr(xref).get("name") != fname:
            hash *= FEATURE_CALL_REF

        # Remember the relationships
        bb_relations[block_ea] = []

        # Iterate the succesors of this basic block
        for succ_block_ea in succs:
          bb_relations[block_ea].append(succ_block_ea)

        # Iterate the predecessors of this basic block
        for pred_block_ea in preds:
          try:
            bb_relations[pred_block_ea].append(block["start_ea"])
          except KeyError:
            bb_relations[pred_block_ea] = [block["start_ea"]]

    # Calculate the strongly connected components
    try:
      strongly_connected = strongly_connected_components(bb_relations)
      # ...and get the number of loops out of it
      for sc in strongly_connected:
        if len(sc) > 1:
          hash *= FEATURE_LOOP
        else:
          if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
            hash *= FEATURE_LOOP

      # And, also, use the number of strongly connected components
      # to calculate another part of the hash.
      hash *= (FEATURE_STRONGLY_CONNECTED ** len(strongly_connected))
    except:
      print("Exception:", str(sys.exc_info()[1]))

    if fname in no_ret_functions():
      hash *= FEATURE_FUNC_NO_RET
    if fname.startswith("flirt."):
      hash *= FEATURE_FUNC_LIB
    # if flags & FUNC_THUNK:
    #   hash *= FEATURE_FUNC_THUNK

    return str(hash)

#-------------------------------------------------------------------------------
def main():
  kgh = CKoretKaramitasHash()

  d = {}
  for f in Functions():
    hash = kgh.calculate(f)
    func_str_ea = "0x%08x" % f
    try:
      d[hash].append(func_str_ea)
    except:
      d[hash] = [func_str_ea]

    print("0x%08x %s" % (f, hash))

  import pprint
  pprint.pprint(d)
  uniques = 0
  for key in d:
    if len(d[key]) > 1:
      print(key, d[key])
    else:
      uniques += 1
  
  print()
  print("Unique hashes", uniques)

if __name__ == "__main__":
  main()
