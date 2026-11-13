#!/usr/bin/env python3
"""
Diaphora, a diffing plugin for Radare2
Copyright (c) 2021, Fernando Domínguez
Copyright (c) 2017, Sergi Alvarez

Based on IDA backend by:
Copyright (c) 2015-2026, Joxean Koret

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

import argparse
import hashlib
import logging
import os
import sys
from typing import Any, Callable, Dict, List, Optional

from r2diaphora import db_backend
from r2diaphora.ida_shim import install_ida_shim, set_active_cache
from r2diaphora.ida_shim.cache import R2BinaryCache
from r2diaphora.upstream import ensure_upstream_on_path, load_upstream_diaphora

LOG_FORMAT = "%(asctime)-15s [%(levelname)s] - %(message)s"
log = logging.getLogger("diaphora.r2")
log.setLevel(logging.INFO)

if not log.handlers:
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    log.addHandler(console)

#: Mapping of the CLI decompiler names to the radare2 commands implementing them.
DECOMPILERS = {
    "ghidra": "pdg",
    "pdc": "pdc",
}

#: Suffix used for SQLite databases.  MariaDB databases are names, not files.
DB_SUFFIX = ".sqlite"


# -----------------------------------------------------------------------------
# Database naming
# -----------------------------------------------------------------------------


def file_digest(filepath: str) -> str:
    """Return the SHA-256 digest of ``filepath`` (streamed, never in memory)."""
    digest = hashlib.sha256()
    with open(filepath, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dbname_for_file(
    filepath: str,
    backend: Optional[str] = None,
    db_dir: Optional[str] = None,
) -> str:
    """Return the database identifier Diaphora would use for ``filepath``.

    SQLite databases are files named ``<sha256>.sqlite`` under ``db_dir``
    (``~/.r2diaphora/dbs`` by default).  MariaDB databases are just named
    ``diaphora_<sha256>``.
    """
    backend = backend or db_backend.get_active_backend()
    digest = file_digest(filepath)
    if backend == "mariadb":
        return f"diaphora_{digest}"
    directory = db_dir or db_backend.get_db_dir()
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, digest + DB_SUFFIX)


# -----------------------------------------------------------------------------
# Export
# -----------------------------------------------------------------------------


def generate_db_for_file(
    filepath: str,
    out_db: Optional[str] = None,
    override_if_existing: bool = False,
    function_filter: Optional[Callable[[Dict[str, Any]], bool]] = None,
    timeout: Optional[int] = None,
    load_pdb: bool = False,
    use_decompiler: bool = True,
    decompiler: str = "ghidra",
    analyze_all: bool = False,
    backend: Optional[str] = None,
    db_dir: Optional[str] = None,
) -> str:
    """Export a Diaphora database for ``filepath`` and return its name.

    ``function_filter`` receives each ``R2BinaryCache.functions`` entry (with
    ``name``, ``size``, ``ninstrs``, ``nbbs``...) and must return ``True`` for
    the functions that should be exported.
    """
    backend = backend or db_backend.get_active_backend()
    if backend not in db_backend.BACKENDS:
        raise ValueError(f"unknown database backend: {backend}")
    db_backend.configure_db_backend(backend, db_dir=db_dir)

    if decompiler not in DECOMPILERS:
        raise ValueError(
            f"unknown decompiler {decompiler!r}; expected one of {sorted(DECOMPILERS)}"
        )

    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)

    if out_db is None:
        out_db = dbname_for_file(filepath, backend=backend, db_dir=db_dir)

    if db_backend.db_exists(out_db):
        if not override_if_existing:
            log.info("Database %s already exists, reusing it", out_db)
            return out_db
        log.info("Dropping database %s as it was requested to override it", out_db)
        db_backend.drop_db(out_db)

    log.info("Generating database %s for file %s", out_db, filepath)

    cache = R2BinaryCache(
        filepath,
        load_pdb=load_pdb,
        decompiler_cmd=DECOMPILERS[decompiler],
        timeout=timeout or 3600,
    )
    install_ida_shim(cache)
    try:
        if function_filter is not None:
            cache.prune_functions(function_filter)

        if use_decompiler:
            # One radare2 process decompiles every function at once; the
            # individual lookups performed by the exporter are then in-memory.
            cache.decompile_all()

        ensure_upstream_on_path()
        _, _, _ = load_upstream_diaphora()
        # ``diaphora_ida`` performs ``from idc import *`` at import time, so it
        # must only be imported once the shim is installed.
        import diaphora_ida  # noqa: WPS433 (import after shim installation)

        bd = diaphora_ida.CIDABinDiff(out_db)
        bd.use_decompiler = use_decompiler
        bd.decompiler_available = bool(
            use_decompiler and cache.decompiler_available is not False
        )
        # Hex-Rays microcode cannot be emulated with radare2/r2ghidra and is
        # only used by a handful of experimental heuristics.
        bd.export_microcode = False
        bd.exclude_library_thunk = not analyze_all
        bd.ida_subs = True

        if bd.export() is not True:
            raise RuntimeError(f"failed to export the database for {filepath}")
    finally:
        set_active_cache(None)
        cache.close()
        db_backend.close_all_connections(out_db)

    return out_db


# -----------------------------------------------------------------------------
# Diffing
# -----------------------------------------------------------------------------

_CHOOSER_KEYS = ("best", "partial", "unreliable")


def _collect_results(bindiff: Any) -> List[dict]:
    """Turn the upstream choosers into plain dictionaries for the HTML report."""
    results: List[dict] = []
    for chooser_name in _CHOOSER_KEYS:
        chooser = getattr(bindiff, f"{chooser_name}_chooser", None)
        chooser_items = getattr(chooser, "items", ()) if chooser is not None else ()
        if not chooser_items:
            # Aborted diff: choosers were never filled; fall back to the
            # incremental match store, whose rows are
            # [ea, name1, ea2, name2, description, ratio, nodes1, nodes2]
            for match in getattr(bindiff, "all_matches", {}).get(chooser_name, ()):
                results.append(
                    {
                        "type": chooser_name,
                        "line": 0,
                        "address": match[0],
                        "name": match[1],
                        "address2": match[2],
                        "name2": match[3],
                        "description": match[4],
                        "ratio": match[5],
                        "nodes1": match[6],
                        "nodes2": match[7],
                        "bb1": match[6],
                        "bb2": match[7],
                    }
                )
            continue
        for row in chooser_items:
            # CChooser.add_item row layout:
            # [index, ea, name, ea2, name2, ratio, nodes1, nodes2, description]
            results.append(
                {
                    "type": chooser_name,
                    "line": row[0],
                    "address": row[1],
                    "name": row[2],
                    "address2": row[3],
                    "name2": row[4],
                    "ratio": row[5],
                    "nodes1": row[6],
                    "nodes2": row[7],
                    "bb1": row[6],
                    "bb2": row[7],
                    "description": row[8],
                }
            )
    results.sort(key=lambda item: (item["type"], -float(item["ratio"])))
    return results


def compare_dbs(
    db1: str,
    db2: str,
    diff_out: Optional[str] = None,
    backend: Optional[str] = None,
    file1: Optional[str] = None,
    file2: Optional[str] = None,
    **diff_opts: Any,
) -> List[dict]:
    """Diff two exported databases and return the matches as dictionaries.

    When ``diff_out`` is given an HTML report is rendered next to the results.
    """
    backend = backend or db_backend.get_active_backend()
    db_backend.configure_db_backend(backend)

    ensure_upstream_on_path()
    diaphora_mod, _, _ = load_upstream_diaphora()

    bindiff = diaphora_mod.CBinDiff(db1)
    try:
        for key, value in diff_opts.items():
            setattr(bindiff, key, value)
        try:
            bindiff.diff(db2)
        except SystemExit:
            # Upstream aborts the whole diff with ``SystemExit`` when one
            # heuristic exceeds its row/time budget - on large binaries
            # 'Related compilation unit' alone produces millions of
            # candidate pairs.  Run the final pass ourselves so the matches
            # collected so far are cleaned up and reach the choosers.
            print(
                "[Diaphora] heuristic budget exceeded; "
                "returning partial results",
                file=sys.stderr,
            )
            try:
                bindiff.final_pass()
            except Exception:
                pass
        matches = _collect_results(bindiff)
    finally:
        try:
            bindiff.db_close()
        except Exception:  # pragma: no cover - already closed by diff()
            pass
        db_backend.close_all_connections(db1)

    if diff_out:
        from r2diaphora.html_diff import HtmlResults

        HtmlResults(
            matches,
            file1=file1,
            file2=file2,
            db1=db1,
            db2=db2,
        ).render(diff_out)

    return matches


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def _looks_like_database(path: str) -> bool:
    return path.lower().endswith(DB_SUFFIX)


def _build_output_name(db1: str, db2: str) -> str:
    base1 = os.path.basename(db1).split(".")[0][:10]
    base2 = os.path.basename(db2).split(".")[0][:10]
    return f"{base1}_vs_{base2}.html"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="r2diaphora",
        description="Export Diaphora databases with radare2 and diff them.",
    )
    parser.add_argument("file1", help="Binary or exported .sqlite database to analyze")
    parser.add_argument(
        "file2", nargs="?", default=None, help="(Optional) file or database to diff against"
    )
    parser.add_argument("-f", dest="force", action="store_true", help="Force DB override")
    parser.add_argument(
        "-nbbs",
        dest="nbbs",
        default=0,
        type=int,
        help="Exclude functions with fewer than this number of basic blocks",
    )
    parser.add_argument(
        "-o",
        dest="output",
        default=None,
        help="HTML output file (default: <db1>_vs_<db2>.html)",
    )
    parser.add_argument(
        "-d",
        "--decompiler",
        default="ghidra",
        choices=sorted(DECOMPILERS),
        help="Decompiler to use for the export",
    )
    parser.add_argument(
        "-nd",
        "--no-decompiler",
        dest="no_decompiler",
        action="store_true",
        help="Do not use the decompiler",
    )
    parser.add_argument(
        "-a",
        dest="analyze_all",
        action="store_true",
        help="Analyze every function (library functions included)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        default=None,
        type=int,
        help="Timeout, in seconds, for each radare2 invocation",
    )
    parser.add_argument(
        "--pdb",
        dest="load_pdb",
        action="store_true",
        help="Let radare2 load PDB symbols, when available",
    )
    parser.add_argument(
        "--db-backend",
        dest="backend",
        default="sqlite",
        choices=list(db_backend.BACKENDS),
        help="Database backend to use (default: sqlite)",
    )
    parser.add_argument(
        "--db-dir",
        dest="db_dir",
        default=None,
        help="Directory holding SQLite databases (default: ~/.r2diaphora/dbs)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)

    db_backend.configure_db_backend(args.backend, db_dir=args.db_dir)

    def function_filter(info: Dict[str, Any]) -> bool:
        if info["name"].startswith("flirt."):
            return False
        return info["nbbs"] >= args.nbbs

    filter_arg = None if args.analyze_all else function_filter

    def resolve(path: str) -> str:
        if _looks_like_database(path):
            return path
        return generate_db_for_file(
            path,
            override_if_existing=args.force,
            function_filter=filter_arg,
            timeout=args.timeout,
            load_pdb=args.load_pdb,
            use_decompiler=not args.no_decompiler,
            decompiler=args.decompiler,
            analyze_all=args.analyze_all,
            backend=args.backend,
            db_dir=args.db_dir,
        )

    db1 = resolve(args.file1)
    if not args.file2:
        print(f"[+] Database saved to {db1}")
        return 0

    db2 = resolve(args.file2)
    output = args.output or _build_output_name(db1, db2)
    matches = compare_dbs(
        db1,
        db2,
        diff_out=output,
        backend=args.backend,
        file1=args.file1 if not _looks_like_database(args.file1) else None,
        file2=args.file2 if not _looks_like_database(args.file2) else None,
    )
    print(f"[+] {len(matches)} matches found; diff saved to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
