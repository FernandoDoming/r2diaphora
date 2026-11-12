import os

from r2diaphora.upstream import ensure_upstream_on_path, load_upstream_diaphora


def test_upstream_diaphora_35_vendored():
    upstream_dir = ensure_upstream_on_path()
    assert os.path.isdir(upstream_dir)
    assert os.path.isfile(os.path.join(upstream_dir, "UPSTREAM_VERSION"))
    assert os.path.isfile(os.path.join(upstream_dir, "diaphora_ida.py"))

    diaphora_mod, heuristics_mod, schema_mod = load_upstream_diaphora()
    assert diaphora_mod.VERSION_VALUE == "3.4"
    assert len(schema_mod.TABLES) == 13
    assert len(schema_mod.INDICES) >= 40
    assert len(heuristics_mod.HEURISTICS) >= 40
    assert len(diaphora_mod.CBinDiff.FUNCTION_FIELDS) == 54
