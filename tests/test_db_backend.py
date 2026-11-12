import os
import sqlite3
import tempfile

from r2diaphora.upstream import load_upstream_diaphora
from r2diaphora.db_backend import (
    RowAdapter,
    configure_db_backend,
    connect_db,
    close_all_connections,
    remove_db_file,
    translate_sqlite_to_mariadb,
    escape_percent_in_literals,
)


def test_row_adapter_supports_key_and_index():
    row = RowAdapter({"id": 7, "name": "wWinMain", "address": "5368715732"})
    assert row["id"] == 7
    assert row[0] == 7
    assert row["name"] == "wWinMain"
    assert row[1] == "wWinMain"
    assert dict(row)["address"] == "5368715732"


def test_translate_sqlite_to_mariadb_preserves_question_marks_in_literals():
    # Review Focus #1: '?' inside string literals (like C++ mangled names) must NOT become '%s'
    sql = (
        "select f.name from main.functions f, diff.functions df "
        "where f.mangled_function = '?__CxxUnhandledExceptionFilter@@YAJPEAU_EXCEPTION_POINTERS@@@Z' "
        "and f.address = ? and df.rva = ?"
    )
    translated = translate_sqlite_to_mariadb(sql, main_db="db_main", diff_db="db_diff")
    assert "'?__CxxUnhandledExceptionFilter@@YAJPEAU_EXCEPTION_POINTERS@@@Z'" in translated
    assert "`db_main`.functions" in translated
    assert "`db_diff`.functions" in translated
    assert translated.count("%s") == 2


def test_translate_all_upstream_heuristics_to_mariadb():
    _, heuristics_mod, schema_mod = load_upstream_diaphora()
    for table_sql in schema_mod.TABLES:
        out = translate_sqlite_to_mariadb(table_sql, main_db="db1", diff_db="db2")
        assert "auto_increment" in out.lower() or "version" in out.lower()
    for heur in heuristics_mod.HEURISTICS:
        sql = heur["sql"].replace("%POSTFIX%", " and f.instructions > 5 ")
        out = translate_sqlite_to_mariadb(sql, main_db="db1", diff_db="db2")
        assert "`db2`.functions" in out or "`db2`.constants" in out or "`db2`.compilation_units" in out
        assert "cast(" not in out.lower() or "as real" not in out.lower()


def test_sqlite_windows_file_lock_cleanup_on_remove():
    # Review Focus #5: open connections must be closed before os.remove on Windows
    configure_db_backend("sqlite")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_lock.sqlite")
        conn = connect_db(db_path)
        conn.execute("create table t (x int)")
        conn.commit()
        remove_db_file(db_path)
        assert not os.path.exists(db_path)


def test_index_text_columns_get_prefix_length():
    out = translate_sqlite_to_mariadb(
        "create index if not exists idx_x on functions(assembly, nodes)", "db1", "db2"
    )
    assert "assembly(255)" in out
    assert "nodes(255)" not in out
    assert "nodes" in out


def test_literal_percent_is_escaped_but_placeholders_are_not():
    sql = "select 1 from t where name not like 'nullsub_%' and x = %s"
    assert escape_percent_in_literals(sql) == "select 1 from t where name not like 'nullsub_%%' and x = %s"
