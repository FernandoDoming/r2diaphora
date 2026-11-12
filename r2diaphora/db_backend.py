"""Dual-backend database layer for Diaphora 3.5.

SQLite is the default and is used through the stdlib ``sqlite3`` module with
no translation. MariaDB is selected with ``configure_db_backend("mariadb")``:
upstream SQL (written for SQLite) is translated on the fly, so the upstream
sources stay unmodified.
"""

import json
import os
import re
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Union

from r2diaphora.upstream import load_upstream_diaphora

BACKENDS = ("sqlite", "mariadb")
DB_ATTRS_FILE = "db.json"
SQLITE_SUFFIXES = ("", "-wal", "-shm", "-crash")
INDEX_TEXT_PREFIX = 255
DEFAULT_DB_DIR = os.path.join(os.path.expanduser("~"), ".r2diaphora", "dbs")

_LITERAL_RE = re.compile(r"('(?:[^']|'')*'|\"(?:[^\"]|\"\")*\")")
_TEXT_UNIQUE_RE = re.compile(r"\b(address|rva|start_ea)\s+text\s+unique\b", re.IGNORECASE)
_INDEX_RE = re.compile(
    r"(create\s+index\s+if\s+not\s+exists\s+\w+\s+on\s+\w+\s*\()([^)]*)\)", re.IGNORECASE
)
_ATTACH_RE = re.compile(r'^\s*attach\s+"?([^"\s]+)"?\s+as\s+diff\s*$', re.IGNORECASE)
_DETACH_RE = re.compile(r'^\s*detach\s+"?(\w+)"?\s*$', re.IGNORECASE)

_state: Dict[str, Any] = {"backend": "sqlite", "db_dir": None, "db_attrs": None}
_registry: List[Any] = []
_registry_lock = threading.Lock()


class RowAdapter:
    """Row that supports both column-name and positional access, like sqlite3.Row."""

    __slots__ = ("_data", "_values")

    def __init__(self, dict_row: Dict[str, Any]):
        self._data = dict(dict_row)
        self._values = tuple(self._data.values())

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return self._values[key]
        return self._data[key]

    def keys(self):
        return self._data.keys()

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


def _text_columns() -> set:
    _, _, schema_mod = load_upstream_diaphora()
    found = set()
    for table_sql in schema_mod.TABLES:
        found.update(re.findall(r"\b(\w+)\s+text\b", table_sql, re.IGNORECASE))
    return found


_TEXT_COLUMNS: Optional[set] = None


def _translate_code(code: str, main_db: str, diff_db: Optional[str]) -> str:
    global _TEXT_COLUMNS
    if _TEXT_COLUMNS is None:
        _TEXT_COLUMNS = _text_columns()

    code = re.sub(r"(?<![\w.`])main\.", f"`{main_db}`.", code)
    if diff_db:
        code = re.sub(r"(?<![\w.`])diff\.", f"`{diff_db}`.", code)
    code = re.sub(r"insert\s+or\s+ignore\s+into", "insert ignore into", code, flags=re.IGNORECASE)
    code = re.sub(r"cast\(([^()]+?)\s+as\s+real\)", r"cast(\1 as double)", code, flags=re.IGNORECASE)
    code = re.sub(
        r"integer\s+primary\s+key\b(?!\s+auto_increment)",
        "integer primary key auto_increment",
        code,
        flags=re.IGNORECASE,
    )
    code = _TEXT_UNIQUE_RE.sub(lambda m: f"{m.group(1)} varchar(255) unique", code)

    def _index_cols(m):
        cols = []
        for col in m.group(2).split(","):
            name = col.strip()
            if name.lower() in _TEXT_COLUMNS:
                cols.append(f"{name}({INDEX_TEXT_PREFIX})")
            else:
                cols.append(name)
        return f"{m.group(1)}{', '.join(cols)})"

    code = _INDEX_RE.sub(_index_cols, code)
    return code.replace("?", "%s")


def translate_sqlite_to_mariadb(sql: str, main_db: str, diff_db: Optional[str] = None) -> str:
    parts = _LITERAL_RE.split(sql)
    out = []
    for i, part in enumerate(parts):
        out.append(part if i % 2 else _translate_code(part, main_db, diff_db))
    return "".join(out)


def escape_percent_in_literals(sql: str) -> str:
    """Escape '%' inside SQL literals for DB-API drivers that always interpolate."""
    parts = _LITERAL_RE.split(sql)
    return "".join(p.replace("%", "%%") if i % 2 else p for i, p in enumerate(parts))


def get_active_backend() -> str:
    return _state["backend"]


def get_db_dir() -> str:
    """Return the directory where SQLite databases are stored."""
    return _state["db_dir"] or DEFAULT_DB_DIR


def get_db_attrs_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".r2diaphora", DB_ATTRS_FILE)


def get_db_attrs() -> Dict[str, Any]:
    if _state["db_attrs"] is not None:
        return _state["db_attrs"]
    path = get_db_attrs_path()
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class MariaDBCursorAdapter:
    def __init__(self, conn: "MariaDBConnectionAdapter", cur):
        self._conn = conn
        self._cur = cur

    def execute(self, sql: str, params=None):
        stripped = sql.strip()
        low = stripped.lower()
        if low.startswith("pragma") or low.startswith("analyze") or low in ("begin", "begin transaction"):
            return self
        if low == "commit":
            self._conn.commit()
            return self
        m = _ATTACH_RE.match(stripped)
        if m:
            self._conn.diff_db = m.group(1)
            return self
        m = _DETACH_RE.match(stripped)
        if m:
            self._conn.diff_db = None
            return self

        translated = translate_sqlite_to_mariadb(stripped, self._conn.main_db, self._conn.diff_db)
        translated = escape_percent_in_literals(translated)
        self._cur.execute(translated, tuple(params) if params is not None else ())
        return self

    def executemany(self, sql: str, seq):
        for params in seq:
            self.execute(sql, params)
        return self

    def _wrap(self, row):
        return None if row is None else RowAdapter(row)

    def fetchone(self):
        return self._wrap(self._cur.fetchone())

    def fetchmany(self, size: int = 1000):
        return [RowAdapter(r) for r in self._cur.fetchmany(size)]

    def fetchall(self):
        return [RowAdapter(r) for r in self._cur.fetchall()]

    def __iter__(self):
        for row in self._cur:
            yield RowAdapter(row)

    @property
    def lastrowid(self):
        return self._cur.lastrowid

    @property
    def rowcount(self):
        return self._cur.rowcount

    def close(self):
        self._cur.close()


class MariaDBConnectionAdapter:
    def __init__(self, main_db: str):
        import mysql.connector

        attrs = get_db_attrs()
        self.main_db = main_db
        self.diff_db: Optional[str] = None
        self._conn = mysql.connector.connect(
            user=attrs.get("user", ""), password=attrs.get("password", ""), host=attrs.get("host", "localhost")
        )
        boot = self._conn.cursor()
        boot.execute(
            f"CREATE DATABASE IF NOT EXISTS `{main_db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
        )
        boot.execute(f"USE `{main_db}`")
        boot.close()

    def cursor(self) -> MariaDBCursorAdapter:
        return MariaDBCursorAdapter(self, self._conn.cursor(dictionary=True, buffered=True))

    def execute(self, sql: str, params=None) -> MariaDBCursorAdapter:
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def _sqlite_connect(db_name: str) -> sqlite3.Connection:
    db = sqlite3.connect(db_name, check_same_thread=False)
    db.text_factory = str
    db.row_factory = sqlite3.Row
    with _registry_lock:
        _registry.append(db_name)
        _registry.append(db)
    return db


def _mariadb_connect(db_name: str) -> MariaDBConnectionAdapter:
    db = MariaDBConnectionAdapter(db_name)
    with _registry_lock:
        _registry.append(db_name)
        _registry.append(db)
    return db


def connect_db(db_name: str) -> Union[sqlite3.Connection, MariaDBConnectionAdapter]:
    if _state["backend"] == "mariadb":
        return _mariadb_connect(db_name)
    return _sqlite_connect(db_name)


def configure_db_backend(
    backend: str = "sqlite", db_dir: Optional[str] = None, db_attrs: Optional[dict] = None
) -> None:
    if backend not in BACKENDS:
        raise ValueError(f"unknown database backend: {backend}")
    _state["backend"] = backend
    _state["db_dir"] = db_dir
    _state["db_attrs"] = db_attrs
    diaphora_mod, _, _ = load_upstream_diaphora()
    diaphora_mod.sqlite3_connect = connect_db


def close_all_connections(db_name: Optional[str] = None) -> None:
    with _registry_lock:
        keep = []
        for i in range(0, len(_registry), 2):
            name, conn = _registry[i], _registry[i + 1]
            if db_name is None or name == db_name:
                try:
                    conn.close()
                except Exception:
                    pass
            else:
                keep.extend([name, conn])
        _registry[:] = keep


def remove_db_file(db_path: str) -> None:
    close_all_connections(db_path)
    for suffix in SQLITE_SUFFIXES:
        path = f"{db_path}{suffix}"
        if os.path.exists(path):
            os.remove(path)


def db_exists(dbname: str) -> bool:
    if _state["backend"] == "mariadb":
        db = _mariadb_connect(dbname)
        try:
            row = db.execute(
                "select schema_name from information_schema.schemata where schema_name = ?", [dbname]
            ).fetchone()
            return row is not None
        finally:
            close_all_connections(dbname)
    return os.path.isfile(dbname)


def drop_db(dbname: str) -> None:
    if _state["backend"] == "mariadb":
        db = _mariadb_connect(dbname)
        try:
            db.execute(f"DROP DATABASE IF EXISTS `{dbname}`")
        finally:
            close_all_connections(dbname)
        return
    remove_db_file(dbname)


def drop_all(db_dir: Optional[str] = None) -> None:
    """Delete every generated analysis database."""
    close_all_connections(None)
    if _state["backend"] == "mariadb":
        attrs = get_db_attrs()
        if not attrs:
            return
        import mysql.connector

        conn = mysql.connector.connect(
            user=attrs.get("user", ""),
            password=attrs.get("password", ""),
            host=attrs.get("host", "localhost"),
        )
        try:
            cur = conn.cursor()
            cur.execute("show databases")
            names = [row[0] for row in cur.fetchall()]
            cur.close()
            for name in names:
                if not name.startswith("diaphora_"):
                    continue
                cur = conn.cursor()
                cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
                cur.close()
        finally:
            conn.close()
        return

    directory = db_dir or get_db_dir()
    if not os.path.isdir(directory):
        return
    for entry in os.listdir(directory):
        if not entry.lower().endswith(".sqlite"):
            continue
        remove_db_file(os.path.join(directory, entry))


def get_function_details(dbname: str, fname: str) -> Optional[RowAdapter]:
    db = connect_db(dbname)
    try:
        return db.execute("SELECT * FROM functions WHERE name = ?", [fname]).fetchone()
    finally:
        close_all_connections(dbname)
