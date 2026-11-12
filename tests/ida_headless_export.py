"""Headless Diaphora 3.5 exporter, meant to run *inside* IDA:

    idat.exe -A -L<log> -S"<this script>" <binary>

Arguments are passed through environment variables because idc.ARGV handling
differs between IDA releases:

    R2DIA_UPSTREAM  path to the vendored upstream/ directory
    R2DIA_SITEPKG   extra site-packages directory to append (for pygments)
    R2DIA_OUT       output .sqlite path
    R2DIA_DECOMP    "1" to use the decompiler, "0" otherwise
"""

import os
import sys

import ida_auto
import idaapi
import idc

# Force the headless code paths in upstream before it is imported: otherwise
# diaphora_ida tries to import Qt bindings and diaphora_ida_ui (not vendored).
idaapi.cvar.batch = 1

UPSTREAM_DIR = os.environ["R2DIA_UPSTREAM"]
SITE_PACKAGES = os.environ.get("R2DIA_SITEPKG")
OUT_DB = os.environ["R2DIA_OUT"]
USE_DECOMPILER = os.environ.get("R2DIA_DECOMP", "0") == "1"

sys.path.insert(0, UPSTREAM_DIR)
if SITE_PACKAGES and SITE_PACKAGES not in sys.path:
    sys.path.append(SITE_PACKAGES)

# The -S script may run while autoanalysis is still in flight; exporting before
# it finishes produces one-instruction stubs. Upstream's own batch entry point
# calls auto_wait() for the same reason.
ida_auto.auto_wait()

ok = False
try:
    import diaphora_ida

    bd = diaphora_ida.CIDABinDiff(OUT_DB)
    bd.use_decompiler = USE_DECOMPILER
    # Match the r2diaphora export flags: no microcode emulation exists on the
    # radare2 side, and library/thunk functions are skipped by default.
    bd.export_microcode = False
    bd.exclude_library_thunk = True
    bd.ida_subs = True
    ok = bd.export() is True
except Exception:
    import traceback

    traceback.print_exc()
    ok = False

idc.qexit(0 if ok else 3)
