"""Process-wide state shared by the ``ida*`` shim modules."""

from typing import Any, Optional

_active_cache: Optional[Any] = None


def set_active_cache(cache: Optional[Any]) -> None:
    global _active_cache
    _active_cache = cache


def get_active_cache() -> Any:
    if _active_cache is None:
        raise RuntimeError(
            "no radare2 binary cache is active; call install_ida_shim(cache) first"
        )
    return _active_cache


def has_active_cache() -> bool:
    return _active_cache is not None
