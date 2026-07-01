from __future__ import annotations

import re
from typing import Protocol


class SearchablePattern(Protocol):
    def search(self, string: str, /) -> object | None: ...


try:
    import re2
except ImportError:  # pragma: no cover - exercised when optional wheel is absent.
    re2 = None


def compile_regex(pattern: str, flags: int = re.I) -> SearchablePattern:
    re2_pattern = compile_regex_or_none(pattern, flags)
    if re2_pattern is not None:
        return re2_pattern
    return re.compile(pattern, flags)


def compile_regex_or_none(pattern: str, flags: int = re.I) -> SearchablePattern | None:
    if re2 is not None:
        re2_pattern = _compile_re2(pattern, flags)
        if re2_pattern is not None:
            return re2_pattern
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def _compile_re2(pattern: str, flags: int) -> SearchablePattern | None:
    if re2 is None or flags & ~(re.I | re.IGNORECASE | re.NOFLAG):
        return None

    options = re2.Options()
    options.case_sensitive = not bool(flags & (re.I | re.IGNORECASE))
    options.log_errors = False
    try:
        return re2.compile(pattern, options=options)
    except re2.error:
        return None
