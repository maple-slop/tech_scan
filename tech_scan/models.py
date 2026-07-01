from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DIM_CDN_WAF_SERVER = "cdn_waf_server"
DIM_FRONTEND = "frontend_framework"
DIM_BACKEND = "backend_framework"
DIM_CMS = "cms"


@dataclass(frozen=True)
class ResourceObservation:
    id: str
    kind: str
    url: str
    final_url: str | None
    status: int | None
    headers: dict[str, str]
    cookies: dict[str, str]
    body: str
    parent_id: str | None = None
    error: str | None = None
    cache_created_at: int | None = None
    cache_updated_at: int | None = None


@dataclass(frozen=True)
class FetchResult:
    input: str
    url: str
    final_url: str | None
    status: int | None
    headers: dict[str, str]
    cookies: dict[str, str]
    body: str
    mode: str
    error: str | None = None
    browser_globals: list[str] = field(default_factory=list)
    script_srcs: list[str] = field(default_factory=list)
    resources: list[ResourceObservation] = field(default_factory=list)
    primary_resource_id: str | None = None
    cached: bool = False

    @property
    def primary_resource(self) -> ResourceObservation:
        if self.primary_resource_id:
            for resource in self.resources:
                if resource.id == self.primary_resource_id:
                    return resource
        if self.resources:
            return self.resources[0]
        return ResourceObservation(
            id="document:0",
            kind="document",
            url=self.url,
            final_url=self.final_url,
            status=self.status,
            headers=self.headers,
            cookies=self.cookies,
            body=self.body,
            error=self.error,
        )

    @property
    def script_resources(self) -> list[ResourceObservation]:
        return [resource for resource in self.resources if resource.kind == "script"]

    @property
    def script_bodies(self) -> list[str]:
        return [resource.body for resource in self.script_resources if resource.body]


@dataclass
class Finding:
    name: str
    dimension: str
    provider: str
    confidence: int
    evidence: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dimension": self.dimension,
            "provider": self.provider,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class TechnologyResult:
    name: str
    dimension: str
    provider: str
    confidence: int
    evidence: list[str]

    @classmethod
    def from_finding(cls, finding: Finding) -> "TechnologyResult":
        return cls(
            name=finding.name,
            dimension=finding.dimension,
            provider=finding.provider,
            confidence=finding.confidence,
            evidence=list(finding.evidence),
        )

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TechnologyResult":
        return cls(
            name=str(data["name"]),
            dimension=str(data["dimension"]),
            provider=str(data["provider"]),
            confidence=int(data["confidence"]),
            evidence=[str(item) for item in data.get("evidence") or []],
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dimension": self.dimension,
            "provider": self.provider,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class Observation:
    kind: str
    name: str
    value: str

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Observation":
        return cls(
            kind=str(data["kind"]),
            name=str(data["name"]),
            value=str(data["value"]),
        )

    def to_json(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "name": self.name,
            "value": self.value,
        }


@dataclass(frozen=True)
class ScanResult:
    input: str
    url: str | None
    final_url: str | None
    status: int | None
    mode: str
    providers: list[str]
    cached: bool
    cache_lookup: str
    cache_stored: bool | None
    cache_reason: str | None
    cache_created_at: int | None
    cache_updated_at: int | None
    observations: list[Observation]
    technologies: list[TechnologyResult]
    error: str | None

    @classmethod
    def validation_error(
        cls,
        raw_target: str,
        mode: str,
        provider_names: list[str],
        error: str,
    ) -> "ScanResult":
        return cls(
            input=raw_target,
            url=None,
            final_url=None,
            status=None,
            mode=mode,
            providers=list(provider_names),
            cached=False,
            cache_lookup="not_applicable",
            cache_stored=None,
            cache_reason=None,
            cache_created_at=None,
            cache_updated_at=None,
            observations=[],
            technologies=[],
            error=error,
        )

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            input=str(data["input"]),
            url=data.get("url"),
            final_url=data.get("final_url"),
            status=data.get("status"),
            mode=str(data["mode"]),
            providers=[str(item) for item in data.get("providers") or []],
            cached=bool(data["cached"]),
            cache_lookup=str(data["cache_lookup"]),
            cache_stored=data.get("cache_stored"),
            cache_reason=data.get("cache_reason"),
            cache_created_at=data.get("cache_created_at"),
            cache_updated_at=data.get("cache_updated_at"),
            observations=[
                Observation.from_json(item)
                for item in data.get("observations") or []
            ],
            technologies=[
                TechnologyResult.from_json(item)
                for item in data.get("technologies") or []
            ],
            error=data.get("error"),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "mode": self.mode,
            "providers": list(self.providers),
            "cached": self.cached,
            "cache_lookup": self.cache_lookup,
            "cache_stored": self.cache_stored,
            "cache_reason": self.cache_reason,
            "cache_created_at": self.cache_created_at,
            "cache_updated_at": self.cache_updated_at,
            "observations": [observation.to_json() for observation in self.observations],
            "technologies": [technology.to_json() for technology in self.technologies],
            "error": self.error,
        }

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_json().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.to_json()[key]
