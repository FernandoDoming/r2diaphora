"""Standalone HTML diff report for :mod:`r2diaphora`.

The report is rendered from the list of match dictionaries produced by
:func:`r2diaphora.diaphora_r2.compare_dbs`.  Function details (prototype,
pseudocode and assembly) are read directly from the exported databases, so the
report works with both SQLite and MariaDB backends.
"""

import difflib
import os
from hashlib import sha256
from typing import Any, Dict, List, Optional

from yattag import Doc

from r2diaphora import db_backend
from r2diaphora.difflibparser import DiffCode, DifflibParser

try:  # python-magic is optional (and usually unavailable on Windows).
    import magic
except ImportError:  # pragma: no cover - depends on the host
    magic = None


class HtmlResults:
    """Render diffing results as a self-contained HTML document."""

    MATCHES_COLUMNS = [
        "type",
        "name",
        "address",
        "bb1",
        "name2",
        "address2",
        "bb2",
        "ratio",
        "description",
    ]
    MATCHES_COLUMN_NAMES = {
        "address": "Address",
        "name2": "Name 2",
        "address2": "Address 2",
        "bb1": "BB1",
        "bb2": "BB2",
    }

    def __init__(
        self,
        results: List[Dict[str, Any]],
        file1: Optional[str] = None,
        file2: Optional[str] = None,
        db1: Optional[str] = None,
        db2: Optional[str] = None,
    ):
        self.results = results or []
        self.file1 = file1
        self.file2 = file2
        self.db1 = db1
        self.db2 = db2
        self.hashes: Dict[str, str] = {}
        self._connections: Dict[str, Any] = {}

    # -- inputs ------------------------------------------------------------

    def get_file_hash(self, file: Optional[str]) -> str:
        if not file:
            return ""
        if file in self.hashes:
            return self.hashes[file]
        digest = sha256()
        with open(file, "rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
        self.hashes[file] = digest.hexdigest()
        return self.hashes[file]

    def get_file_magic(self, file: Optional[str]) -> str:
        if not file:
            return "Unknown"
        if magic is not None:
            try:
                return magic.Magic().from_file(file)
            except Exception:  # libmagic can be missing even when import works
                pass
        return "Unknown file type (python-magic is not available)"

    # -- database access ---------------------------------------------------

    def _connect(self, db_name: str):
        if db_name not in self._connections:
            self._connections[db_name] = db_backend.connect_db(db_name)
        return self._connections[db_name]

    def get_function_details(
        self, db_name: Optional[str], address: Optional[str]
    ) -> Optional[Any]:
        """Return ``(prototype, pseudocode, assembly)`` for ``address``."""
        if not db_name or not address:
            return None
        try:
            numeric_address = str(int(str(address), 16))
        except (TypeError, ValueError):
            return None

        try:
            connection = self._connect(db_name)
        except Exception:
            return None

        cursor = None
        try:
            cursor = connection.execute(
                "select prototype, pseudocode, assembly from functions where address = ?",
                [numeric_address],
            )
            return cursor.fetchone()
        except Exception:
            return None
        finally:
            if cursor is not None and hasattr(cursor, "close"):
                cursor.close()

    def close(self) -> None:
        for connection in self._connections.values():
            try:
                connection.close()
            except Exception:
                pass
        self._connections.clear()

    # -- rendering helpers -------------------------------------------------

    def interpolate_color(self, color_a, color_b, alpha):
        """Linearly interpolate two RGB tuples."""
        return tuple(
            int((b - a) * alpha + a) for a, b in zip(color_a, color_b)
        )

    @staticmethod
    def _pseudocode(row: Optional[Any]) -> Optional[str]:
        if row is None:
            return None
        prototype = row["prototype"]
        pseudocode = row["pseudocode"]
        if not pseudocode:
            return None
        if prototype:
            return f"{prototype}\n{pseudocode}"
        return pseudocode

    @staticmethod
    def _assembly(row: Optional[Any]) -> Optional[str]:
        if row is None:
            return None
        assembly = row["assembly"]
        return assembly or None

    @staticmethod
    def _changes(left: Optional[str], right: Optional[str]) -> List[dict]:
        if not left or not right:
            return []
        parser = DifflibParser(
            [f"{line}\n" for line in left.split("\n")],
            [f"{line}\n" for line in right.split("\n")],
        )
        return list(parser)

    def _render_side(self, doc, tag, text, changes: List[dict], side: int) -> None:
        for change in changes:
            code = change["code"]
            if code == DiffCode.SIMILAR:
                with tag("span", klass="equal"):
                    text(change["line"])
            elif code == side:
                klass = "deleted" if side == DiffCode.LEFTONLY else "added"
                with tag("span", klass=klass):
                    text(change["line"])
            elif code == DiffCode.CHANGED and side == DiffCode.LEFTONLY:
                with tag("span", klass="deleted"):
                    text(change["line"])
            elif code == DiffCode.CHANGED and side == DiffCode.RIGHTONLY:
                with tag("span", klass="added"):
                    text(change["newline"])
            else:
                with tag("span", klass="blank"):
                    text("\n")

    def _render_tab(self, doc, tag, text, changes: List[dict], index: int, name: str) -> None:
        with tag("div", id=f"diff-{index}-{name.lower()}", klass="tab-pane active"):
            with tag("div", klass="row"):
                for side, title in (
                    (DiffCode.LEFTONLY, "Primary"),
                    (DiffCode.RIGHTONLY, "Secondary"),
                ):
                    with tag("pre", klass=f"col-md-6 {name.lower()}-tab", title=title):
                        self._render_side(doc, tag, text, changes, side)

    # -- rendering ---------------------------------------------------------

    def render(self, filepath: str) -> None:
        doc, tag, text = Doc().tagtext()

        with tag("style"):
            doc.asis(
                """
            .code {
                font-family: monospace;
                background-color: #ddd;
                padding: 20px;
                border-radius: 5px;
                color: #666;
            }

            table.table {
                margin: 15px;
            }

            table.table-dark {
                --bs-table-bg: #303538;
                --bs-table-striped-bg: #303538;
            }

            table.table tbody {
                font-family: monospace;
                font-size: 16px;
            }

            table.table>tbody>tr {
                color: #ccc;
                line-height: 30px;
            }

            .green { color: rgb(126, 211, 33); }
            .orange { color: rgb(245, 166, 35); }
            .yellow { color: rgb(216, 203, 42); }
            .red { color: rgb(255, 65, 89); }

            .hidden-row {
                padding: 0 !important;
            }

            .pseudocode-tab, .assembly-tab {
                position: relative;
                border-radius: 20px;
                margin-top: 30px;
            }

            .pseudocode-tab > span, .assembly-tab > span {
                display: block;
                width: 100%;
                overflow: hidden;
            }

            span.equal { background-color: #0d1117; }
            span.blank { background-color: #0d1117ab; }
            span.deleted { background-color: #301a1f; }
            span.added { background-color: #12261e; }

            .nav-pills a.nav-link.active, .nav-pills .show>a.nav-link {
                background-color: #e91e63;
            }

            a.nav-link { color: #e91e63; }
            a.nav-link:focus, a.nav-link:hover { color: #ee4f84; }

            i.bi { cursor: pointer; }
            """
            )

        with tag("html"):
            with tag("head"):
                doc.stag(
                    "link",
                    rel="stylesheet",
                    href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.2/dist/css/bootstrap.min.css",
                )
                doc.stag(
                    "link",
                    rel="stylesheet",
                    href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/bootstrap-icons.css",
                )
                with tag("script", src="https://code.jquery.com/jquery-3.6.0.slim.min.js"):
                    pass
                with tag(
                    "script",
                    src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.2/dist/js/bootstrap.bundle.min.js",
                ):
                    pass

            with tag(
                "body",
                style="margin: 50px; background-color: #303538; color: white;",
            ):
                for index, path in enumerate([self.file1, self.file2]):
                    if not path:
                        continue
                    with tag("div", klass="row"):
                        with tag("div", klass="col-md-12"):
                            with tag("p", klass="code"):
                                text(f"File {index + 1}: {path}")
                                doc.stag("br")
                                text(f"Type: {self.get_file_magic(path)}")
                                doc.stag("br")
                                text(f"SHA256: {self.get_file_hash(path)}")

                with tag("h5"):
                    text(f"Found {len(self.results)} matches across compared files")

                with tag("div", klass="row"):
                    with tag(
                        "table",
                        klass="table table-dark table-hover align-middle",
                        style="width: 98%;",
                    ):
                        with tag("thead", klass="thead-dark"):
                            with tag("tr"):
                                doc.stag("th")
                                for column in self.MATCHES_COLUMNS:
                                    with tag("th"):
                                        text(self.MATCHES_COLUMN_NAMES.get(column, column.capitalize()))
                        with tag("tbody"):
                            for index, result in enumerate(self.results):
                                self._render_row(doc, tag, text, index, result)

        with open(filepath, "w", encoding="utf-8") as stream:
            stream.write(doc.getvalue())

        self.close()

    def _render_row(self, doc, tag, text, index: int, result: dict) -> None:
        with tag("tr"):
            with tag("th"):
                with tag(
                    "i",
                    ("data-bs-toggle", "collapse"),
                    ("data-bs-target", f"#diff-{index}"),
                    klass="collapse-control",
                    href=f"#diff-{index}",
                ):
                    doc.stag("i", klass="bi bi-chevron-bar-expand")
            for column in self.MATCHES_COLUMNS:
                style = ""
                if column == "ratio":
                    ratio = float(result[column])
                    color = self.interpolate_color((255, 65, 89), (126, 211, 33), ratio)
                    style = f"color: rgb({color[0]}, {color[1]}, {color[2]})"
                value = result[column]
                with tag("th", style=style):
                    text(f"0x{value}" if column in ("address", "address2") else str(value))

        with tag("tr", klass="nohover"):
            with tag("td", colspan=12, klass="hidden-row"):
                with tag("div", klass="accordion-body collapse", id=f"diff-{index}"):
                    details1 = self.get_function_details(self.db1, result.get("address"))
                    details2 = self.get_function_details(self.db2, result.get("address2"))

                    pseudo_changes = self._changes(
                        self._pseudocode(details1), self._pseudocode(details2)
                    )
                    asm_changes = self._changes(
                        self._assembly(details1), self._assembly(details2)
                    )

                    with tag(
                        "nav",
                        klass="nav nav-pills justify-content-center",
                        style="margin-bottom: 20px;",
                    ):
                        with tag("a", klass="nav-link active", href=f"#diff-{index}-pseudocode"):
                            text("Pseudocode")
                        with tag("a", klass="nav-link", href=f"#diff-{index}-assembly"):
                            text("Assembly")

                    with tag("div", klass="tab-content"):
                        if pseudo_changes:
                            self._render_tab(doc, tag, text, pseudo_changes, index, "pseudocode")
                        else:
                            self._render_tab(doc, tag, text, asm_changes, index, "assembly")
                        if pseudo_changes:
                            with tag(
                                "div",
                                id=f"diff-{index}-assembly",
                                klass="tab-pane",
                                style="display: none;",
                            ):
                                with tag("div", klass="row"):
                                    for side in (DiffCode.LEFTONLY, DiffCode.RIGHTONLY):
                                        with tag("pre", klass="col-md-6 assembly-tab"):
                                            self._render_side(doc, tag, text, asm_changes, side)
