import magic
import difflib
from yattag import Doc
from hashlib import sha256

from r2diaphora import get_function_details
from .difflibparser import DifflibParser, DiffCode

class HtmlResults():

    results = []
    MATCHES_COLUMNS = ["type", "name", "address", "bb1", "name2", "address2", "bb2", "ratio", "description"]
    MATCHES_COLUMN_NAMES = {
        "address": "Address",
        "name2": "Name 2",
        "address2": "Address 2",
        "bb1": "BB1",
        "bb2": "BB2"
    }

    def __init__(self, results, file1 = None, file2 = None):
        self.results = results
        self.file1 = file1
        self.file2 = file2
        self.hashes = {}

    def get_file_hash(self, file):
        if file in self.hashes:
            return self.hashes[file]

        hash = ""
        with open(file, "rb") as f:
            d = f.read()
            hash = sha256(d).hexdigest();
        # Cache the result to not compute it multiple times
        self.hashes[file] = hash
        return hash

    def get_file_magic(self, file):
        m = magic.Magic()
        return m.from_file(file)

    def interpolate_color(self, color_a, color_b, alpha):
        # color_a and color_b should be tuples of 3 ints
        r_r = (color_b[0] - color_a[0]) * alpha + color_a[0]
        r_g = (color_b[1] - color_a[1]) * alpha + color_a[1]
        r_b = (color_b[2] - color_a[2]) * alpha + color_a[2]
        return (r_r, r_g, r_b)

    def render(self, filepath):
        doc, tag, text = Doc().tagtext()
        with tag("style"):
            doc.asis("""
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

            .green {
                color: rgb(126, 211, 33);
            }

            .orange {
                color: rgb(245, 166, 35);
            }

            .yellow {
                color: rgb(216, 203, 42);
            }

            .red {
                color: rgb(255, 65, 89);
            }

            i.bi {
                color: #f44336;
            }

            .hidden-row {
                padding: 0 !important;
            }

            .pseudocode-tab {
                position: relative;
                border-radius: 20px;
                margin-top: 30px;
            }

            .pseudocode-tab > span {
                display: block;
                width: 100%;
                overflow: hidden;
            }

            span.equal {
                background-color: #0d1117;
            }

            span.blank {
                background-color: #0d1117ab;
            }

            span.deleted {
                background-color: #301a1f;
            }

            span.added {
                background-color: #12261e;
            }

            .nav-pills a.nav-link.active, .nav-pills .show>a.nav-link {
                background-color: #e91e63;
            }

            a.nav-link {
                color: #e91e63;
            }

            a.nav-link:focus, a.nav-link:hover {
                color: #ee4f84;
            }

            .table-hover>tbody>tr.nohover:hover>* {
                color: inherit;
                --bs-table-accent-bg: inherit;
            }

            i.bi {
                cursor: pointer;
            }
            """)

        with tag("html"):
            with tag("head"):
                doc.stag("link", rel="stylesheet", href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.2/dist/css/bootstrap.min.css")
                doc.stag("link", rel="stylesheet", href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/bootstrap-icons.css")
                with tag("script", src="https://code.jquery.com/jquery-3.6.0.slim.min.js"):
                    pass
                with tag("script", src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.2/dist/js/bootstrap.bundle.min.js"):
                    pass

            with tag("body", style="margin: 50px; background-color: #303538; color: white;"):
                for i, f in enumerate([self.file1, self.file2]):
                    if not f:
                        continue

                    with tag("div", klass="row"):
                        with tag("div", klass="col-md-12"):
                            with tag("p", klass="code"):
                                text(f"File {i + 1}: {f}")
                                doc.stag("br")
                                text(f"Type: {self.get_file_magic(f)}")
                                doc.stag("br")
                                text(f"SHA256: {self.get_file_hash(f)}")

                with tag("h5"):
                    text(f"Found {len(self.results)} matches across compared files")

                with tag("div", klass="row"):
                    with tag("table", 
                            klass="table table-dark table-hover align-middle",
                            style="width: 98%;"):
                        with tag("thead", klass="thead-dark"):
                            with tag("tr"):
                                doc.stag("th")
                                for attr in self.MATCHES_COLUMNS:
                                    with tag("th"):
                                        text(self.MATCHES_COLUMN_NAMES.get(attr, attr.capitalize()))
                        with tag("tbody"):
                            for i, r in enumerate(self.results):
                                # Match row
                                with tag("tr"):
                                    # Expand button
                                    with tag("th"):
                                        with tag("i",
                                                ("data-bs-toggle", "collapse"),
                                                ("data-bs-taget", f"#diff-{i}"),
                                                klass="collapse-control",
                                                href=f"#diff-{i}"):
                                            doc.stag("i", klass="bi bi-chevron-bar-expand")
                                    # Info columns
                                    for attr in self.MATCHES_COLUMNS:
                                        style = ""
                                        if attr == "ratio":
                                            ratio = float(r[attr])
                                            color = self.interpolate_color((255, 65, 89), (126, 211, 33), ratio)
                                            style = f"color: rgb({color[0]}, {color[1]}, {color[2]})"

                                        with tag("th", style=style):
                                                text(f"0x{r[attr]}" if attr in ["address", "address2"] else r[attr])
                                    # /Info columns
                                # Diff
                                with tag("tr", klass="nohover"):
                                    with tag("td", colspan=12, klass="hidden-row"):
                                        with tag("div", klass="accordion-body collapse", id=f"diff-{i}"):
                                            details1 = get_function_details(self.get_file_hash(self.file1), r["name"])
                                            pseudo1 = None
                                            if details1["prototype"] and details1["pseudocode"]:
                                                pseudo1 = details1["prototype"] + "\n" + details1["pseudocode"]
                                            details2 = get_function_details(self.get_file_hash(self.file2), r["name2"])
                                            pseudo2 = None
                                            if details2["prototype"] and details2["pseudocode"]:
                                                pseudo2 = details2["prototype"] + "\n" + details2["pseudocode"]

                                            changes = []
                                            if pseudo1 and pseudo2:
                                                diff = DifflibParser(
                                                    [f"{l}\n" for l in pseudo1.split("\n")],
                                                    [f"{l}\n" for l in pseudo2.split("\n")],
                                                )
                                                changes = [d for d in diff]

                                            # Tabs
                                            with tag("nav", klass="nav nav-pills justify-content-center", style="margin-bottom: 20px;"):
                                                for j, tab in enumerate(["Pseudocode", "Assembly", "Callgraph"]):
                                                    cls = "nav-link"
                                                    if j == 0:
                                                        cls += " active"
                                                    with tag("a", ("data-toggle", "tab"), klass=cls, href=f"#diff-{i}-{tab.lower()}"):
                                                        text(tab)
                                            # Tabs content
                                            with tag("div", klass="tab-content"):
                                                for j, tab in enumerate(["Pseudocode", "Assembly", "Callgraph"]):
                                                    cls = "tab-pane"
                                                    if j == 0:
                                                        cls += " active"

                                                    if tab == "Pseudocode":
                                                        if not pseudo1 or not pseudo2:
                                                            cls += " disabled"

                                                        with tag("div", klass=cls, id=f"diff-{i}-{tab.lower()}"):
                                                            with tag("div", klass="row"):
                                                                for side in [DiffCode.LEFTONLY, DiffCode.RIGHTONLY]:
                                                                    cls = "col-md-6"
                                                                    with tag("pre", klass=f"col-md-6 {tab.lower()}-tab"):
                                                                        for change in changes:
                                                                            if change["code"] == DiffCode.SIMILAR:
                                                                                with tag("span", klass="equal"):
                                                                                    text(change["line"])
                                                                            elif change["code"] == side:
                                                                                with tag(
                                                                                    "span",
                                                                                    klass=f"{'deleted' if side == DiffCode.LEFTONLY else 'added'}"
                                                                                ):
                                                                                    text(change["line"])
                                                                            elif change["code"] == DiffCode.CHANGED and side == DiffCode.LEFTONLY:
                                                                                with tag("span", klass="deleted"):
                                                                                    text(change["line"])
                                                                            elif change["code"] == DiffCode.CHANGED and side == DiffCode.RIGHTONLY:
                                                                                with tag("span", klass="added"):
                                                                                    text(change["newline"])
                                                                            else:
                                                                                with tag("span", klass="blank"):
                                                                                    text("\n")

                                                    elif tab == "Assembly":
                                                        pass

                                                    elif tab == "Callgraph":
                                                        pass


        result = doc.getvalue()
        with open(filepath, "w") as f:
            f.write(result)
