__version__ = "0.1.0"
__author__ = "Fernando Domínguez"
__credits__ = "Joxean Koret"

from .diaphora_r2 import generate_db_for_file, dbname_for_file, compare_dbs
from .diaphora import (
    get_function_details, get_db_attrs, get_db_attrs_path, drop_all,
    drop_db, db_exists as sample_db_exists
)
from .html_diff import HtmlResults

def version():
    return __version__

