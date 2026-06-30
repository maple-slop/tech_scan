from __future__ import annotations

import json
import subprocess
from typing import Iterable

from tech_scan.models import FetchResult, Finding

from .base import Provider
from .wappalyzer_json import WAPPALYZER_DIMENSION_MAP


class WappalyzerGoProvider(Provider):
    name = "wappalyzergo"

    def __init__(self, command: str):
        self.command = command

    def detect(self, fetch: FetchResult) -> list[Finding]:
        payload = {
            "url": fetch.final_url or fetch.url,
            "headers": fetch.headers,
            "body": fetch.body,
        }
        try:
            proc = subprocess.run(
                [self.command],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                check=True,
                timeout=20,
            )
            raw = json.loads(proc.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return []

        return self._parse_output(raw)

    def _parse_output(self, raw: object) -> list[Finding]:
        technologies: Iterable[dict[str, object]]
        if isinstance(raw, dict) and isinstance(raw.get("technologies"), list):
            technologies = raw["technologies"]  # type: ignore[assignment]
        elif isinstance(raw, list):
            technologies = raw  # type: ignore[assignment]
        else:
            return []

        findings: list[Finding] = []
        for tech in technologies:
            if not isinstance(tech, dict):
                continue
            categories = tech.get("categories") or tech.get("category") or []
            if isinstance(categories, str):
                categories = [categories]
            dimension = None
            for category in categories:
                mapped = WAPPALYZER_DIMENSION_MAP.get(str(category).lower())
                if mapped:
                    dimension = mapped
                    break
            if not dimension:
                continue
            name = str(tech.get("name") or "").strip()
            if not name:
                continue
            confidence = int(tech.get("confidence") or 80)
            findings.append(
                Finding(
                    name=name,
                    dimension=dimension,
                    provider=self.name,
                    confidence=max(0, min(confidence, 100)),
                    evidence=["wappalyzergo provider"],
                )
            )
        return findings
