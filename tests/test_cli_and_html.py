import os

import pytest

from r2diaphora.diaphora_r2 import compare_dbs, generate_db_for_file
from r2diaphora.html_diff import HtmlResults


CALC = r"C:\Windows\System32\calc.exe"
pytestmark = pytest.mark.skipif(
    not os.path.exists(CALC), reason="calc.exe is not available"
)


def test_export_and_diff_workflow_generates_matches_and_html(tmp_path):
    db1 = str(tmp_path / "calc1.sqlite")
    db2 = str(tmp_path / "calc2.sqlite")
    html_out = str(tmp_path / "diff.html")

    out1 = generate_db_for_file(
        CALC,
        out_db=db1,
        override_if_existing=True,
        use_decompiler=False,
        backend="sqlite",
    )
    out2 = generate_db_for_file(
        CALC,
        out_db=db2,
        override_if_existing=True,
        use_decompiler=False,
        backend="sqlite",
    )
    assert out1 == db1 and os.path.isfile(db1)
    assert out2 == db2 and os.path.isfile(db2)

    matches = compare_dbs(db1, db2, backend="sqlite")
    assert len(matches) >= 15
    assert all(m["type"] == "best" and float(m["ratio"]) == 1.0 for m in matches)

    HtmlResults(matches, file1=CALC, file2=CALC, db1=db1, db2=db2).render(html_out)
    assert os.path.isfile(html_out)
    with open(html_out, "r", encoding="utf-8") as stream:
        html_content = stream.read()
    assert "Found " in html_content
    assert "0x1400017cc" in html_content.lower()


def test_dbname_for_file_uses_sha256_and_db_dir(tmp_path):
    from r2diaphora.diaphora_r2 import dbname_for_file

    name = dbname_for_file(CALC, backend="sqlite", db_dir=str(tmp_path))
    assert os.path.dirname(name) == str(tmp_path)
    assert os.path.basename(name) == (
        "621ba3934afc45c35a4ee16386f4da30119f39fa243e8dc8fef3491a76f829d8.sqlite"
    )
