# r2diaphora

r2diaphora is a port of [Diaphora](https://github.com/joxeankoret/diaphora) 3.5 to
[radare2](https://github.com/radareorg/radare2). It uses
[r2ghidra](https://github.com/radareorg/r2ghidra) as decompiler by default, with
support for `pdc` and for no decompiler at all.

## What is diaphora?

Quoting from the original repository:

> Diaphora (διαφορά, Greek for 'difference') is the most advanced program diffing
> tool, working as an IDA plugin (...). It was released first during SyScan 2015
> and is actively maintained.

## How it works

Diaphora 3.5 itself is vendored **unmodified** under `r2diaphora/upstream/`. A
translation layer (`r2diaphora/ida_shim/`) implements the subset of the IDAPython
API that Diaphora uses on top of a single bulk radare2 analysis, so upstream code
keeps working as-is and future Diaphora releases only need to be re-vendored.

Exported databases use **SQLite by default** (`~/.r2diaphora/dbs/<sha256>.sqlite`)
and are byte-compatible in schema with the ones produced by Diaphora inside IDA.
MariaDB is still supported with `--db-backend mariadb`. Databases exported by
either side can be diffed against each other — pass a `.sqlite` path as `file1`
or `file2`.

All radare2 analysis data is prefetched in bulk inside a single `r2` invocation
per phase (analysis dump, then batch decompilation chunked across
`min(4, cpu_count)` workers; `R2DIA_WORKERS` overrides). There is no
per-instruction IPC.

## Decompilers

- `ghidra` (default) — r2ghidra `pdgj`. Its p-code ops feed the
  pseudocode-primes hash, so it produces the strongest matching.
- `pdc` (`-d pdc`) — radare2's built-in text decompiler, like the original
  r2diaphora port. Works without r2ghidra installed; pseudocode is
  assembly-flavoured C. The `pdct` region tree is parsed into hash material,
  so pseudocode-prime hashes still discriminate (coarser than `pdgj`).
- `-nd` — skip decompilation entirely.

## Library and thunk recognition

Like IDA's exporter, r2diaphora drops recognized library code and thunks from
the export by default (`-a` keeps them):

- **Thunks** (`FUNC_THUNK`) — detected by radare2 itself: analysis marks
  single-block jump stubs with the `thunk` function attribute (`aflj`
  `"thunk": true`, `attrs` letter `T`, manageable via `afia`). This covers
  PLT/import stubs, `jmp [IAT]` wrappers including Borland/Delphi `mjmp`
  encodings, and tail-jump thunks without local heuristics. Requires an r2
  build that detects thunks during analysis; older builds mark nothing.
- **Library code** (`FUNC_LIB`) — FLIRT signature matching via radare2's
  `zfs`, plus r2's `library` function attribute (`aflj` `attrs` letter `L`,
  user-set via `afia+ library`). If `dir.flirt` (populated by
  `r2pm -i sigdb` or manually dropped `.sig` files) or the `R2DIA_FLIRT` env
  var provides signatures, matched functions are marked library code and
  renamed to the library symbol name, exactly like IDA. Without a sigdb nothing is marked. Note the community
  sigdb ships MSVC/mingw/masm signatures but no Delphi RTL set — Delphi
  FLIRT sigs must be supplied separately.

## Differences from IDA-produced databases

Without a sigdb, r2diaphora exports tend to contain **more** functions than
the IDA exporter on the same binary. IDA marks library/runtime code
`FUNC_LIB` via FLIRT/Lumina signatures and one-instruction IAT jumps
`FUNC_THUNK`; the Diaphora exporter drops both by default. On a 4 MB Borland
Delphi sample, IDA found 3,854 functions but exported only ~663 after
dropping 2,759 `FUNC_LIB` + 432 `FUNC_THUNK`. With matching sigdb coverage
r2diaphora lands much closer; the residual difference is Delphi RTL
signatures IDA ships and the community sigdb does not, plus ordinary
analysis divergence.

## Performance

Measured full-export wall-clock (r2 pipeline vs `idat -A` headless IDA export,
Windows, benign System32 binaries):

| Binary   | Functions | r2diaphora | IDA export |
|----------|-----------|------------|------------|
| whoami   | ~240      | 4.6 s      | 7.0 s      |
| cmd      | ~990      | 20.0 s     | 18.2 s     |
| conhost  | ~4,600    | 48.4 s     | 59.7 s     |
| explorer | ~8,700    | 749 s      | 367 s      |

Up to ~5K functions the port is at parity or faster. On larger binaries the
remaining gap is upstream Diaphora's own export loop plus batch `pdgj`
decompilation — `R2DIA_WORKERS=8` helps on wider machines.

Known limits: the upstream *Related compilation unit* heuristic is quadratic
in candidate pairs and hits the 5-minute `SQL_TIMEOUT_LIMIT` on 4 MB+,
5K-function binaries; `compare_dbs` then returns the matches accumulated so
far instead of dying. `pdgj` has ~0.5% run-to-run nondeterminism in
register-name inference (an r2ghidra property, not a parallelism artifact).

## Safety

r2diaphora only ever opens samples for static reading through radare2. It
never executes, emulates, or debugs target binaries.

## Setup

0. r2diaphora requires radare2 (with r2ghidra for decompilation). Install radare2
   and add its `bin` directory to `PATH`.
1. Install it with `pip install r2diaphora` (or `pip install -e .` from a checkout).
2. (Optional) Install r2ghidra with `r2pm -ci r2ghidra`. You can also use `pdc`
   (`-d pdc`) or no decompiler at all (`-nd`).
3. (Optional, MariaDB only) Run
   `r2diaphora-db config -u <user> -p <password> -hs <host>
   --backend mariadb`.

## Usage

```
usage: r2diaphora [-h] [-f] [-nbbs NBBS] [-o O] [-d {ghidra,pdc}] [-nd] [-a]
                  [-t TIMEOUT] [--pdb] [--db-backend {mariadb,sqlite}]
                  [--db-dir DB_DIR] file1 [file2]

positional arguments:
  file1                 Binary or exported .sqlite database to analyze
  file2                 (Optional) file or database to diff against

options:
  -h, --help            show this help message and exit
  -f                    Force DB override
  -nbbs NBBS            Exclude functions with fewer than this number of basic blocks
  -o O                  HTML output file (default: <db1>_vs_<db2>.html)
  -d, --decompiler {ghidra,pdc}
                        Decompiler to use for the export
  -nd, --no-decompiler  Do not use the decompiler
  -a                    Analyze ALL functions (library functions included)
  -t, --timeout TIMEOUT
                        Timeout, in seconds, for each radare2 invocation
  --pdb                 Let radare2 load PDB symbols, when available
  --db-backend {mariadb,sqlite}
                        Database backend to use (default: sqlite)
  --db-dir DB_DIR       Directory holding SQLite databases
                        (default: ~/.r2diaphora/dbs)
```

```python
from r2diaphora import generate_db_for_file, compare_dbs, HtmlResults

db1 = generate_db_for_file("original.exe")
db2 = generate_db_for_file("patched.exe")
matches = compare_dbs(db1, db2)
HtmlResults(matches, file1="original.exe", file2="patched.exe", db1=db1, db2=db2).render("diff.html")
```

```
usage: r2diaphora-db [-h] {clean,config} ...

positional arguments:
  {clean,config}
    clean         delete analysis databases
    config        configure credentials for the MariaDB server

options:
  -h, --help      show this help message and exit
```

```
usage: r2diaphora-bulk [-h] [-f] [-a] [-nbbs NBBS] [-d {ghidra,pdc}] [-nd]
                       [-t TIMEOUT] [--pdb] [--db-backend {mariadb,sqlite}]
                       [--db-dir DB_DIR] files [files ...]

positional arguments:
  files       Files to analyze

options:
  -h, --help  show this help message and exit
  -f          Force DB override
  -a          Analyze ALL functions (by default library functions are skipped)
```
