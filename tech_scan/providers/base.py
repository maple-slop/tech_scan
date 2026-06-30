from __future__ import annotations

from tech_scan.models import FetchResult, Finding


class Provider:
    name: str

    def detect(self, fetch: FetchResult) -> list[Finding]:
        raise NotImplementedError
