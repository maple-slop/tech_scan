from __future__ import annotations

from .base import Provider
from .builtin import BuiltinProvider
from .wappalyzergo import WappalyzerGoProvider


def build_providers(
    provider_names: list[str],
) -> list[Provider]:
    enabled: list[Provider] = []
    names = {"builtin", "wappalyzergo"} if "all" in provider_names else set(provider_names)
    if "builtin" in names:
        enabled.append(BuiltinProvider())
    if "wappalyzergo" in names:
        enabled.append(WappalyzerGoProvider())
    return enabled
