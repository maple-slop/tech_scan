from __future__ import annotations

import json
from importlib import resources
from typing import Any

from .wappalyzer_json import WappalyzerJsonProvider


DATA_PACKAGE = "tech_scan.providers.data.wappalyzergo"
FINGERPRINTS_FILE = "fingerprints_data.json"


def load_vendored_fingerprints() -> dict[str, Any]:
    data = resources.files(DATA_PACKAGE).joinpath(FINGERPRINTS_FILE).read_text(encoding="utf-8")
    loaded = json.loads(data)
    return loaded if isinstance(loaded, dict) else {}


class WappalyzerGoProvider(WappalyzerJsonProvider):
    name = "wappalyzergo"

    def __init__(self, data: dict[str, Any] | None = None):
        super().__init__(data=data or load_vendored_fingerprints(), provider_name=self.name)
