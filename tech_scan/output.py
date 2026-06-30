from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse


RESET = "\033[0m"
COLORS = {
    "dim": "\033[2m",
    "green": "\033[32m",
    "bright_green": "\033[1;32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
}


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS[color]}{text}{RESET}"


def format_jsonl(result: dict[str, Any]) -> str:
    return json.dumps(result, sort_keys=True)


def origin_display_url(result: dict[str, Any]) -> str:
    for value in [result.get("url"), result.get("input")]:
        if not value:
            continue
        text = str(value)
        parsed = urlparse(text if "://" in text else f"https://{text}")
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/"
    return "<unknown>"


def status_color(status: object, error: object) -> str:
    if error:
        return "red"
    try:
        code = int(status)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "yellow"
    if 200 <= code < 400:
        return "green"
    if 400 <= code < 500:
        return "yellow"
    return "red"


def confidence_color(confidence: object) -> str:
    try:
        score = int(confidence)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "dim"
    if score >= 90:
        return "bright_green"
    if score >= 75:
        return "green"
    if score >= 50:
        return "yellow"
    return "dim"


def evidence_color(evidence: object) -> str:
    text = str(evidence).lower()
    strong_markers = [
        "header",
        "cookie",
        "csrf",
        "viewstate",
        "state field",
        "wappalyzer header",
        "wappalyzer cookie",
        "wappalyzer meta",
        "wappalyzer script",
    ]
    weak_markers = [
        "url suffix",
        "implied",
        "generic",
        "no evidence",
    ]
    if any(marker in text for marker in strong_markers):
        return "green"
    if any(marker in text for marker in weak_markers):
        return "dim"
    if any(marker in text for marker in ["body", "html", "script", "meta", "global", "js", "marker"]):
        return "yellow"
    return "yellow"


def format_human(result: dict[str, Any], color: bool = True) -> str:
    technologies = result.get("technologies") or []
    tech_names = [str(tech.get("name", "")) for tech in technologies if tech.get("name")]
    summary = ", ".join(tech_names) if tech_names else "no technologies"
    display_url = origin_display_url(result)
    status = result.get("status")
    error = result.get("error")
    status_text = str(status) if status is not None else "no status"
    status_style = status_color(status, error)

    lines = [
        " ".join(
            [
                colorize(str(display_url), "bold", color),
                colorize(status_text, status_style, color),
                colorize(summary, "cyan", color),
            ]
        )
    ]
    lines.extend(
        [
            f"  input: {result.get('input')}",
            f"  url: {result.get('url')}",
            f"  final_url: {result.get('final_url')}",
            f"  status: {colorize(status_text, status_style, color)}",
            f"  mode: {result.get('mode')}",
            f"  providers: {', '.join(result.get('providers') or [])}",
            f"  cached: {result.get('cached')}",
            f"  cache_created_at: {result.get('cache_created_at')}",
            f"  cache_updated_at: {result.get('cache_updated_at')}",
            f"  error: {colorize(str(error), 'red', color) if error else None}",
        ]
    )
    observations = result.get("observations") or []
    if observations:
        lines.append("  observations:")
        for item in observations:
            kind = item.get("kind")
            name = item.get("name")
            value = item.get("value")
            lines.append(f"     {kind}: {name}: {value}")
    else:
        lines.append("  observations: none")

    if not technologies:
        lines.append("  technologies: none")
        return "\n".join(lines)

    lines.append("  technologies:")
    for index, tech in enumerate(technologies, start=1):
        name = colorize(str(tech.get("name")), "bold", color)
        confidence = tech.get("confidence")
        confidence_text = colorize(str(confidence), confidence_color(confidence), color)
        lines.append(
            "  "
            f"{index}. {name}: dimension={tech.get('dimension')}, "
            f"provider={tech.get('provider')}, confidence={confidence_text}"
        )
        evidence = tech.get("evidence") or []
        if evidence:
            for item in evidence:
                lines.append(f"     evidence: {colorize(str(item), evidence_color(item), color)}")
        else:
            lines.append(f"     evidence: {colorize('none', evidence_color('no evidence'), color)}")
    return "\n".join(lines)


def format_result(result: dict[str, Any], output: str, color: bool) -> str:
    if output == "jsonl":
        return format_jsonl(result)
    return format_human(result, color=color)
