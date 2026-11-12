"""Shim layer that lets unmodified IDA code run on top of radare2.

The heart of the package is :class:`R2BinaryCache`, which drives a single
radare2 session and stores everything Diaphora needs in memory.  The ``idc``,
``idaapi``, ``idautils`` and ``ida_*`` modules in this package are thin
re-exports of :mod:`r2diaphora.ida_shim.api`; :func:`install_ida_shim` registers
them in ``sys.modules`` so that unmodified upstream code can simply
``import idc``.
"""

import importlib
import sys

from r2diaphora.ida_shim import state
from r2diaphora.ida_shim.cache import R2BinaryCache, find_r2_binary

__all__ = [
    "R2BinaryCache",
    "find_r2_binary",
    "install_ida_shim",
    "set_active_cache",
    "get_active_cache",
    "SHIM_MODULES",
]

# Every module name that upstream Diaphora (or its bundled helpers) imports.
SHIM_MODULES = (
    "idc",
    "idaapi",
    "idautils",
    "ida_bytes",
    "ida_funcs",
    "ida_gdl",
    "ida_graph",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_pro",
    "ida_segment",
    "ida_ua",
)


def set_active_cache(cache):
    """Make ``cache`` the backing store used by the ``ida*`` shim."""
    state.set_active_cache(cache)


def get_active_cache():
    return state.get_active_cache()


def install_ida_shim(cache=None):
    """Register the shim modules in ``sys.modules`` and activate ``cache``.

    Must be called before importing the vendored upstream modules, because
    ``diaphora_ida`` performs ``from idc import *`` at import time.
    """
    if cache is not None:
        state.set_active_cache(cache)
    if not state.has_active_cache():
        raise RuntimeError("install_ida_shim() requires a cache or an active cache")

    for name in SHIM_MODULES:
        module = importlib.import_module("r2diaphora.ida_shim." + name)
        sys.modules[name] = module

    # IDAPython leaks its sibling modules through ``from idaapi import *``; a
    # lot of upstream code relies on that (e.g. ``graph_hashes`` uses
    # ``ida_ua`` without importing it).  Replicate the leak.
    modules = {name: sys.modules[name] for name in SHIM_MODULES}
    for module in modules.values():
        for name, sibling in modules.items():
            setattr(module, name, sibling)

    return state.get_active_cache()
