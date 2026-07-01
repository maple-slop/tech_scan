from __future__ import annotations

from tech_scan.models import DIM_BACKEND, DIM_FRONTEND, FetchResult, Finding

from .base import Provider
from .builtin_rules import IMPLIED_BACKENDS, IMPLIED_FRONTENDS, RULES
from .signals import DetectionSignals


class BuiltinProvider(Provider):
    name = "builtin"

    def detect(self, fetch: FetchResult) -> list[Finding]:
        findings: dict[tuple[str, str], Finding] = {}
        context = DetectionSignals.from_fetch(fetch)

        for rule in RULES:
            evidence = rule.detect(fetch, context)
            if not evidence:
                continue

            key = (rule.name.lower(), rule.dimension)
            existing = findings.get(key)
            if existing:
                existing.confidence = max(existing.confidence, rule.confidence)
                for item in evidence:
                    if item not in existing.evidence:
                        existing.evidence.append(item)
            else:
                findings[key] = Finding(
                    name=rule.name,
                    dimension=rule.dimension,
                    provider=self.name,
                    confidence=rule.confidence,
                    evidence=list(dict.fromkeys(evidence)),
                )

        self._add_implied_backends(findings)
        self._add_implied_frontends(findings)
        return list(findings.values())

    def _add_implied_backends(
        self, findings: dict[tuple[str, str], Finding]
    ) -> None:
        for source, (implied_name, confidence) in IMPLIED_BACKENDS.items():
            source_key = (source.lower(), DIM_BACKEND)
            implied_key = (implied_name.lower(), DIM_BACKEND)
            if source_key not in findings or implied_key in findings:
                continue
            findings[implied_key] = Finding(
                name=implied_name,
                dimension=DIM_BACKEND,
                provider=self.name,
                confidence=confidence,
                evidence=[f"implied by: {source}"],
            )

    def _add_implied_frontends(
        self, findings: dict[tuple[str, str], Finding]
    ) -> None:
        for source, (implied_name, confidence) in IMPLIED_FRONTENDS.items():
            source_key = (source.lower(), DIM_FRONTEND)
            implied_key = (implied_name.lower(), DIM_FRONTEND)
            if source_key not in findings or implied_key in findings:
                continue
            findings[implied_key] = Finding(
                name=implied_name,
                dimension=DIM_FRONTEND,
                provider=self.name,
                confidence=confidence,
                evidence=[f"implied by: {source}"],
            )
