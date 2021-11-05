__author__ = "Fernando Domínguez"
__credits__ = "Joxean Koret"

from .diaphora_r2 import generate_db_for_file, dbname_for_file, compare_dbs
from .diaphora import (
    get_function_details, get_db_attrs, get_db_attrs_path, drop_all,
    drop_db, db_exists as sample_db_exists
)
from .idaapi.idaapi_to_r2 import get_all_fns, strings, string_values, r2_open, r2_close
from .html_diff import HtmlResults


