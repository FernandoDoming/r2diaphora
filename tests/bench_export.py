"""Wall-clock benchmark: r2diaphora export vs IDA headless export.

Times the full pipeline on each side for the same benign binaries:

- r2: R2BinaryCache analysis (bulk radare2 prefetch) -> decompile_all ->
  upstream CIDABinDiff.export()
- IDA: idat.exe -A (autoanalysis) + tests/ida_headless_export.py

Usage: python tests/bench_export.py <binary> <workdir>
"""
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

IDA_DIR = r"C:\Program Files\IDA Professional 9.5"
IDAT = os.path.join(IDA_DIR, "idat.exe")
IDA_EXPORT_SCRIPT = os.path.join(REPO_ROOT, "tests", "ida_headless_export.py")


def export_r2(binary, out_db):
    """Mirror generate_db_for_file() with per-phase timers."""
    from r2diaphora.diaphora_r2 import (
        DECOMPILERS,
        ensure_upstream_on_path,
        load_upstream_diaphora,
    )
    from r2diaphora.ida_shim import install_ida_shim, set_active_cache
    from r2diaphora.ida_shim.cache import R2BinaryCache
    from r2diaphora import db_backend

    db_backend.configure_db_backend("sqlite")
    phases = {}

    t0 = time.perf_counter()
    cache = R2BinaryCache(binary, decompiler_cmd=DECOMPILERS["ghidra"], timeout=3600)
    phases["r2_analysis"] = time.perf_counter() - t0

    install_ida_shim(cache)
    try:
        t0 = time.perf_counter()
        cache.decompile_all()
        phases["r2_decompile"] = time.perf_counter() - t0

        ensure_upstream_on_path()
        load_upstream_diaphora()
        import diaphora_ida

        bd = diaphora_ida.CIDABinDiff(out_db)
        bd.use_decompiler = True
        bd.decompiler_available = bool(cache.decompiler_available is not False)
        bd.export_microcode = False
        bd.exclude_library_thunk = True
        bd.ida_subs = True

        t0 = time.perf_counter()
        ok = bd.export()
        phases["r2_export"] = time.perf_counter() - t0
        if ok is not True:
            raise RuntimeError("export failed")
        phases["r2_total"] = sum(phases.values())
        phases["functions"] = len(cache.functions)
    finally:
        set_active_cache(None)
        cache.close()
    return phases


def export_ida(binary, out_db, workdir):
    log_path = os.path.join(workdir, "ida_export.log")
    idb_path = os.path.join(
        workdir, os.path.splitext(os.path.basename(binary))[0] + ".i64"
    )
    env = dict(os.environ)
    env.update(
        {
            "R2DIA_UPSTREAM": os.path.join(REPO_ROOT, "r2diaphora", "upstream"),
            "R2DIA_SITEPKG": os.path.join(
                os.path.expanduser("~"),
                "AppData",
                "Roaming",
                "Python",
                f"Python{sys.version_info.major}{sys.version_info.minor}",
                "site-packages",
            ),
            "R2DIA_OUT": out_db,
            "R2DIA_DECOMP": "1",
        }
    )
    cmd = [
        IDAT,
        "-A",
        f"-L{log_path}",
        f"-o{idb_path}",
        f'-S"{IDA_EXPORT_SCRIPT}"',
        binary,
    ]
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd, cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    total = time.perf_counter() - t0
    if proc.returncode != 0 or not os.path.isfile(out_db):
        tail = ""
        if os.path.isfile(log_path):
            with open(log_path, "r", errors="replace") as fh:
                tail = fh.read()[-2000:]
        raise RuntimeError(
            f"IDA export failed rc={proc.returncode}\n"
            f"{proc.stdout.decode('utf-8', 'replace')[-1500:]}\n{tail}"
        )
    return total


def main():
    binary, workdir = sys.argv[1], sys.argv[2]
    os.makedirs(workdir, exist_ok=True)
    name = os.path.basename(binary)

    t0 = time.perf_counter()
    ida_total = export_ida(binary, os.path.join(workdir, "ida.sqlite"), workdir)

    r2 = export_r2(binary, os.path.join(workdir, "r2.sqlite"))
    print(
        f"RESULT {name}: size={os.path.getsize(binary)} funcs={r2['functions']} "
        f"r2_analysis={r2['r2_analysis']:.1f}s r2_decompile={r2['r2_decompile']:.1f}s "
        f"r2_export={r2['r2_export']:.1f}s r2_total={r2['r2_total']:.1f}s "
        f"ida_total={ida_total:.1f}s"
    )


if __name__ == "__main__":
    main()
