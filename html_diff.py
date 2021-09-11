from yattag import Doc
from hashlib import sha256

class HtmlResults():

    results = []
    MATCHES_COLUMNS = ["name", "address", "name2", "address2", "ratio", "description"]
    MATCHES_COLUMN_NAMES = {
        "address": "Address",
        "name2": "Name 2",
        "address2": "Address 2",
    }

    def __init__(self, results, file1 = None, file2 = None):
        self.results = results
        self.file1 = file1
        self.file2 = file2

    def get_file_hash(self, file):
        hash = ""
        with open(file, "rb") as f:
            d = f.read()
            hash = sha256(d).hexdigest();
        return hash

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

            .table {
                margin: 15px;
            }

            .table tbody {
                font-family: monospace;
                font-size: 16px;
                color: #ccc;
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
            """)

        with tag("html"):
            with tag("head"):
                doc.stag("link", rel="stylesheet", href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css")

            with tag("body", style="margin: 50px; background-color: #303538; color: white;"):
                if self.file1:
                    with tag("div", klass="row"):
                        with tag("div", klass="col-md-12"):
                            with tag("p", klass="code"):
                                text(f"File 1: {self.file1}")
                                doc.stag("br")
                                text(f"SHA256: {self.get_file_hash(self.file1)}")

                if self.file2:
                    with tag("div", klass="row"):
                        with tag("div", klass="col-md-12"):
                            with tag("p", klass="code"):
                                text(f"File 2: {self.file2}")
                                doc.stag("br")
                                text(f"SHA256: {self.get_file_hash(self.file2)}")

                with tag("h5"):
                    text(f"Found {len(self.results)} matches across compared files")

                with tag("div", klass="row"):
                    with tag("table", klass="table table-dark table-hover"):
                        with tag("thead", klass="thead-dark"):
                            with tag("tr"):
                                for attr in self.MATCHES_COLUMNS:
                                    with tag("th"):
                                        text(self.MATCHES_COLUMN_NAMES.get(attr, attr.capitalize()))
                        with tag("tbody"):
                            for r in self.results:
                                with tag("tr"):
                                    for attr in self.MATCHES_COLUMNS:
                                        style = ""
                                        if attr == "ratio":
                                            ratio = float(r[attr])
                                            color = self.interpolate_color((255, 65, 89), (126, 211, 33), ratio)
                                            style = f"color: rgb({color[0]}, {color[1]}, {color[2]})"

                                        with tag("th", style=style):
                                                text(f"0x{r[attr]}" if attr in ["address", "address2"] else r[attr])

        result = doc.getvalue()
        with open(filepath, "w") as f:
            f.write(result)
