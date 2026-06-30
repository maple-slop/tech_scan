from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources
from urllib.parse import urlparse


DATA_PACKAGE = "tech_scan.fetchers.data.adblock"
LIST_FILES = ["easylist.txt", "easyprivacy.txt"]


def _rule_to_regex(rule: str) -> re.Pattern[str] | None:
    rule = rule.strip()
    if (
        not rule
        or rule.startswith("!")
        or rule.startswith("@@")
        or "##" in rule
        or "#@#" in rule
        or "#?#" in rule
    ):
        return None
    pattern = rule.split("$", 1)[0]
    if not pattern or pattern.startswith("["):
        return None
    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        return None

    prefix = ""
    if pattern.startswith("||"):
        prefix = r"^https?://([^/?#]+\.)?"
        pattern = pattern[2:]
    elif pattern.startswith("|"):
        prefix = "^"
        pattern = pattern[1:]

    suffix = ""
    if pattern.endswith("|"):
        suffix = "$"
        pattern = pattern[:-1]

    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*")
    escaped = escaped.replace(r"\^", r"(?:[^\w.%_-]|$)")
    try:
        return re.compile(prefix + escaped + suffix, re.I)
    except re.error:
        return None


@lru_cache(maxsize=1)
def _compiled_rules() -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for name in LIST_FILES:
        text = resources.files(DATA_PACKAGE).joinpath(name).read_text(encoding="utf-8")
        for line in text.splitlines():
            rule = _rule_to_regex(line)
            if rule is not None:
                compiled.append(rule)
    return tuple(compiled)


def is_blocked_script_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return True
    return any(rule.search(url) for rule in _compiled_rules())
