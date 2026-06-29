from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DIM_CDN_WAF_SERVER = "cdn_waf_server"
DIM_FRONTEND = "frontend_framework"
DIM_BACKEND = "backend_framework"


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
    cached: bool = False


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
