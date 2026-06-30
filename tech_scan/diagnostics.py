from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass, field
from typing import TextIO


@dataclass
class Diagnostics:
    verbosity: int = 0
    stream: TextIO = field(default_factory=lambda: sys.stderr)

    def enabled(self, level: int) -> bool:
        return self.verbosity >= level

    def log(self, level: int, message: str) -> None:
        if self.enabled(level):
            print(f"[tech-scan] {message}", file=self.stream, flush=True)

    def exception(self, level: int, message: str, exc: BaseException) -> None:
        if self.enabled(level):
            print(f"[tech-scan] {message}: {exc}", file=self.stream, flush=True)
            print(traceback.format_exc(), file=self.stream, end="", flush=True)


def short_exception(exc: BaseException) -> str:
    return str(exc)


def exception_with_traceback(exc: BaseException, message: str | None = None) -> str:
    prefix = message if message is not None else str(exc)
    return f"{prefix}\n{traceback.format_exc()}"
