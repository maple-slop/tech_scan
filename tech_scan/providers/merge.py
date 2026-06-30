from __future__ import annotations

from typing import Iterable

from tech_scan.models import Finding


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.name.lower(), finding.dimension)
        existing = merged.get(key)
        if not existing:
            merged[key] = Finding(
                name=finding.name,
                dimension=finding.dimension,
                provider=finding.provider,
                confidence=finding.confidence,
                evidence=list(finding.evidence),
            )
            continue
        existing.confidence = max(existing.confidence, finding.confidence)
        providers = set(existing.provider.split(","))
        providers.add(finding.provider)
        existing.provider = ",".join(sorted(providers))
        for evidence in finding.evidence:
            if evidence not in existing.evidence:
                existing.evidence.append(evidence)
    return sorted(merged.values(), key=lambda item: (item.dimension, item.name.lower()))
