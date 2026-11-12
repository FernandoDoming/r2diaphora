"""Ad-hoc IDA-vs-r2 Diaphora parity check for any binary.

Usage::

    python tests/compare_any_dbs.py <binary> [workdir]

Runs the vendored Diaphora 3.5 exporter inside ``idat.exe -A -S`` and
``r2diaphora`` on the same file, then reports:

* function coverage (shared / only-IDA / only-r2)
* per-column metric mismatches over shared functions
* instruction-level code/data/call xref presence diffs
* the upstream diff engine's best/partial matches (all must be
  same-address pairs for identical binaries)
"""

import os
import sqlite3
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for path in (REPO_ROOT, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from compare_calc_dbs import (  # noqa: E402
    BOUNDED_DIFF_COLUMNS,
    EXACT_METRIC_COLUMNS,
    export_ida_db,
)
from r2diaphora.diaphora_r2 import compare_dbs, generate_db_for_file  # noqa: E402


def _rows(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    out = {int(r["address"]): dict(r) for r in conn.execute("select * from functions")}
    conn.close()
    return out


def compare(binary, workdir):
    os.makedirs(workdir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(binary))[0]
    ida_db = export_ida_db(
        os.path.join(workdir, f"{stem}_ida.sqlite"), workdir, binary
    )
    r2_db = generate_db_for_file(
        binary,
        out_db=os.path.join(workdir, f"{stem}_r2.sqlite"),
        override_if_existing=True,
        use_decompiler=True,
        backend="sqlite",
    )
    ida, r2 = _rows(ida_db), _rows(r2_db)
    shared = sorted(set(ida) & set(r2))
    only_ida = sorted(set(ida) - set(r2))
    only_r2 = sorted(set(r2) - set(ida))

    print(f"\n=== {binary} ===")
    print(
        f"functions: ida={len(ida)} r2={len(r2)} shared={len(shared)} "
        f"only_ida={len(only_ida)} only_r2={len(only_r2)} "
        f"recall={len(shared) / max(1, len(ida)):.1%}"
    )
    if only_ida:
        print("  only IDA:", [(hex(a), ida[a]["name"]) for a in only_ida[:10]])
    if only_r2:
        print("  only r2 :", [(hex(a), r2[a]["name"]) for a in only_r2[:10]])

    bad = {}
    for column in EXACT_METRIC_COLUMNS + list(BOUNDED_DIFF_COLUMNS):
        diffs = [
            ea for ea in shared
            if ida[ea].get(column) != r2[ea].get(column)
        ]
        allowed = BOUNDED_DIFF_COLUMNS.get(column, 0)
        mark = "" if len(diffs) <= allowed else "  <-- OVER BUDGET"
        if diffs or allowed:
            print(f"  {column}: {len(diffs)} diffs (allowed {allowed}){mark}")
            if diffs and len(diffs) <= 8:
                print("    ", [hex(a) for a in diffs])
            bad[column] = diffs

    matches = compare_dbs(ida_db, r2_db, backend="sqlite")
    best = [m for m in matches if m["type"] == "best"]
    partial = [m for m in matches if m["type"] == "partial"]
    wrong = [m for m in matches if m["address"] != m["address2"]]
    low = [m for m in matches if float(m["ratio"]) < 0.9]
    print(
        f"diff: best={len(best)} partial={len(partial)} "
        f"matched={len(set(m['address'] for m in matches) & set(hex(a) for a in shared))}/{len(shared)}"
    )
    if wrong:
        print("  WRONG-ADDRESS PAIRS:", [(m["address"], m["address2"]) for m in wrong])
    if low:
        print("  low-ratio:", [(m["address"], m["ratio"]) for m in low])
    return ida_db, r2_db


if __name__ == "__main__":
    binary = sys.argv[1]
    workdir = sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp(prefix="r2dia_cmp_")
    print("workdir:", workdir)
    compare(binary, workdir)
