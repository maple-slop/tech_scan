from __future__ import annotations

import argparse
import os
from pathlib import Path

from .fetchers.browser import browser_extension_identity, chromium_executable_path


def ca_bundle_env_default() -> Path | None:
    for name in ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"]:
        value = os.environ.get(name)
        if value:
            return Path(value).expanduser()
    return None


def tls_identity(ca_bundle: Path | None, insecure: bool) -> str:
    if insecure:
        return "insecure"
    if ca_bundle:
        return f"ca:{ca_bundle.expanduser().resolve()}"
    return "default"


def requests_verify(ca_bundle: Path | None, insecure: bool) -> bool | str | None:
    if insecure:
        return False
    if ca_bundle:
        return str(ca_bundle.expanduser().resolve())
    return None


def chromium_identity() -> str:
    executable_path = chromium_executable_path()
    if executable_path:
        return f"chromium:{Path(executable_path).expanduser().resolve()}"
    return "chromium:playwright-default"


def fetch_identity(args: argparse.Namespace, mode: str) -> str:
    parts = [tls_identity(args.ca_bundle, args.insecure)]
    if mode == "browser":
        parts.append(browser_extension_identity(not getattr(args, "no_browser_extension", False)))
        parts.append(chromium_identity())
    return "|".join(parts)
