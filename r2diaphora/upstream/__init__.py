"""Unmodified upstream Diaphora 3.5 sources, vendored into r2diaphora.

Upstream modules import each other by top-level name (``import ml``,
``from jkutils.factor import ...``), so the vendored directory itself has to be
on ``sys.path``. Nothing in this directory may be edited by hand; see
UPSTREAM_VERSION for the pinned source.
"""

import importlib
import os
import sys
from types import ModuleType
from typing import Tuple

UPSTREAM_DIR = os.path.dirname(os.path.abspath(__file__))


def ensure_upstream_on_path() -> str:
    if UPSTREAM_DIR not in sys.path:
        sys.path.insert(0, UPSTREAM_DIR)
    return UPSTREAM_DIR


def load_upstream_diaphora() -> Tuple[ModuleType, ModuleType, ModuleType]:
    ensure_upstream_on_path()
    diaphora_mod = importlib.import_module("diaphora")
    heuristics_mod = importlib.import_module("diaphora_heuristics")
    schema_mod = importlib.import_module("db_support.schema")
    return diaphora_mod, heuristics_mod, schema_mod
