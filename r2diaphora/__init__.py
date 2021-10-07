__version__ = "0.1.0"
__author__ = "Fernando Domínguez"
__credits__ = "Joxean Koret"

from .diaphora_r2 import generate_db_for_file, dbname_for_file, compare_dbs
from .diaphora import db_exists as sample_db_exists
from .html_diff import HtmlResults

def version():
    return __version__

