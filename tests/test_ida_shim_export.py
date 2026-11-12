import os
import sqlite3
import tempfile

import pytest

from r2diaphora.db_backend import configure_db_backend, close_all_connections
from r2diaphora.ida_shim import install_ida_shim, set_active_cache
from r2diaphora.ida_shim.cache import R2BinaryCache
from r2diaphora.upstream import ensure_upstream_on_path


CALC = r"C:\Windows\System32\calc.exe"
pytestmark = pytest.mark.skipif(
    not os.path.exists(CALC), reason="calc.exe is not available"
)


def test_unmodified_diaphora_ida_exports_calc_exe():
    ensure_upstream_on_path()
    configure_db_backend("sqlite")
    cache = R2BinaryCache(CALC, load_pdb=False)
    install_ida_shim(cache)
    try:
        import diaphora_ida

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "calc_test.sqlite")
            bd = diaphora_ida.CIDABinDiff(db_path)
            bd.use_decompiler = True
            bd.export_microcode = False
            assert bd.export() is True
            close_all_connections(db_path)

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                ver = conn.execute("select value from version").fetchone()["value"]
                assert ver == "3.4"
                prog = conn.execute("select * from program").fetchone()
                assert prog["processor"] == "metapc64"
                assert prog["md5sum"] == "18e5b970eab39020b7e53aa81c371287"

                funcs = conn.execute("select * from functions").fetchall()
                assert len(funcs) >= 15
                by_addr = {int(r["address"]): r for r in funcs}
                # Check RtlpImageNtHeader (0x1400017cc)
                assert 0x1400017CC in by_addr
                f_rtl = by_addr[0x1400017CC]
                assert f_rtl["nodes"] == 8
                assert f_rtl["instructions"] == 25
                assert f_rtl["pseudocode"] is not None
                assert int(f_rtl["pseudocode_primes"]) > 1
            finally:
                conn.close()
    finally:
        set_active_cache(None)
        cache.close()
