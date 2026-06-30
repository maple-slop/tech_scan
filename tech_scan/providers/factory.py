from __future__ import annotations

from pathlib import Path

from .base import Provider
from .builtin import BuiltinProvider
from .wappalyzer_json import WappalyzerJsonProvider
from .wappalyzergo import WappalyzerGoProvider


def build_providers(
    provider_names: list[str],
    wappalyzergo_cmd: str | None,
    wappalyzer_data: Path | str | None = None,
) -> list[Provider]:
    enabled: list[Provider] = []
    names = {"builtin", "wappalyzergo", "wappalyzer_json"} if "all" in provider_names else set(provider_names)
    if "builtin" in names:
        enabled.append(BuiltinProvider())
    if "wappalyzer_json" in names and wappalyzer_data:
        enabled.append(WappalyzerJsonProvider(wappalyzer_data))
    if "wappalyzergo" in names and wappalyzergo_cmd:
        enabled.append(WappalyzerGoProvider(wappalyzergo_cmd))
    return enabled
