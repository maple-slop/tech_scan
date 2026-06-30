from .auto import (
    browser_fallback_reason,
    has_useful_response,
    looks_js_required,
    looks_spa_shell,
    should_try_browser,
)
from .browser import (
    BrowserSession,
    browser_extension_identity,
    chromium_executable_path,
    fetch_browser,
    ubol_extension_path,
)
from .headers import BROWSER_HEADERS
from .requests import (
    extract_script_srcs,
    fetch_requests,
    is_redirect_status,
    redirect_target,
    same_hostname,
)

__all__ = [
    "BROWSER_HEADERS",
    "BrowserSession",
    "browser_fallback_reason",
    "browser_extension_identity",
    "chromium_executable_path",
    "extract_script_srcs",
    "fetch_browser",
    "fetch_requests",
    "has_useful_response",
    "is_redirect_status",
    "looks_js_required",
    "looks_spa_shell",
    "redirect_target",
    "same_hostname",
    "should_try_browser",
    "ubol_extension_path",
]
