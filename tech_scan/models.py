from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DIM_CDN_WAF_SERVER = "cdn_waf_server"
DIM_FRONTEND = "frontend_framework"
DIM_BACKEND = "backend_framework"


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
