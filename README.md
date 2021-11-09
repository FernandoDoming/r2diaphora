# r2diaphora

r2diaphora is a port of [Diaphora](https://github.com/joxeankoret/diaphora) to [radare2](https://github.com/radareorg/radare2) and MariaDB. It also uses [r2ghidra](https://github.com/radareorg/r2ghidra) as decompiler by default, with support for other decompilers such as `pdc`.

## What is diaphora?

Quoting from the original repository:

> Diaphora (διαφορά, Greek for 'difference') version 2.0 is the most advanced program diffing tool, working as an IDA plugin, available as of today (2019). It was released first during SyScan 2015 and is actively maintained.

## Setup

0. r2diaphora requires radare2 to be installed in the local machine and a valid connection to a MariaDB server. If you don't have either of those refer to the respective software manual on how to install them.
1. Install it with `pip install r2diaphora`
2. Run `r2diaphora-db config -u <user> -p <password> -hs <host>` to fill database credentials
3. (Optional) Install r2ghidra with `r2pm -ci r2ghidra`. Optionally you can use `pdc` (`-d pdc`) or no decompiler at all (`-nd`)

## Usage

```
usage: r2diaphora [-h] [-f] [-nbbs NBBS] [-o O] [-d {pdc,ghidra}] [-nd] [-a] file1 [file2]

positional arguments:
  file1                 File to analyze
  file2                 (Optional) File to diff against

optional arguments:
  -h, --help            show this help message and exit
  -f                    Force DB override
  -nbbs NBBS            Functions with a number of basic blocks below this number are excluded from analysis
  -o O                  Diff output file (HTML) - Default value: <db1name>_vs_<db2name>.html
  -d {pdc,ghidra}, --decompiler {pdc,ghidra}
                        Which decompiler to use
  -nd, --no-decompiler  Do not use the decompiler
  -a                    Analyze ALL functions (by default library functions are skipped)
```

```
usage: r2diaphora-db [-h] {clean,config} ...

positional arguments:
  {clean,config}
    clean         delete analysis databases
    config        configure credentials for the MariaDB server

optional arguments:
  -h, --help      show this help message and exit
```

```
usage: r2diaphora-bulk [-h] [-f] [-a] files [files ...]

positional arguments:
  files       Files to analyze

optional arguments:
  -h, --help  show this help message and exit
  -f          Force DB override
  -a          Analyze ALL functions (by default library functions are skipped)
```