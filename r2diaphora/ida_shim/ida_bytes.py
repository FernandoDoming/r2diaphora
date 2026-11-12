"""Drop-in stand-in for IDA's ``ida_bytes`` module (radare2 backend)."""

import sys

from r2diaphora.ida_shim.api import *  # noqa: F401,F403

# Upstream Diaphora uses both ``from idc import *`` and ``idc.get_...``; exporting
# the module under its own name keeps the latter working.
ida_bytes = sys.modules[__name__]
