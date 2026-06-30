# AGENTS.md

## Project Purpose

`tech_scan` is a Python CLI for bug bounty technology triage. It reads domains or URLs from stdin, fetches each site, detects familiar web technologies, and prints either human-readable output or JSON Lines.

Current detection scope is intentionally focused on three dimensions:

- `cdn_waf_server`
- `frontend_framework`
- `backend_framework`

Do not expand into analytics, payment, auth, ads, or broad CMS-style reporting unless the user explicitly asks.

## CLI Behavior

Common commands:

```bash
echo 'https://example.com' | uv run -m tech_scan
echo 'https://example.com' | uv run -m tech_scan --mode requests --output jsonl
echo 'https://example.com' | CHROMIUM_PATH=/usr/bin/chromium uv run -m tech_scan --mode browser
echo 'https://example.com' | uv run -m tech_scan --mode auto --verbosity 1
echo 'https://example.com' | uv run -m tech_scan --sanity-timeout 0.5
echo 'https://example.com' | uv run -m tech_scan --proxy http://127.0.0.1:8080 --ca-bundle ~/.mitmproxy/mitmproxy-ca-cert.pem
echo 'https://example.com' | uv run -m tech_scan --proxy socks5h://127.0.0.1:1080 --insecure
uv run -m tech_scan --provider wappalyzergo < domains.txt
uv run -m tech_scan --provider wappalyzer_json --wappalyzer-data fingerprints_data.json < domains.txt
```

Fetch modes:

- `requests`: browser-like HTTP request headers, no JavaScript execution.
- `browser`: Playwright Chromium rendering.
- `auto`: requests first, browser only for likely missed content: request errors, `401`/`403`/`429`/`503`, no useful response, explicit JavaScript-required text, or sparse SPA shells with no useful findings.

Output modes:

- `human`: default, multi-line colorized output.
- `jsonl`: one stable JSON object per input line.

Human output must include all fields present in JSONL.

Diagnostics:

- `--verbosity 0`: default, short error messages only.
- `--verbosity 1`: adds fetcher-switch reasons and redirect traces on stderr.
- `--verbosity 2`: includes stack traces for live top-level fetch failures and stderr exception diagnostics.
- `--verbosity 3`: adds detailed cache, fetch, browser, resource, provider, and timing logs on stderr.
- Keep verbose diagnostics on stderr so JSONL stdout remains one machine-readable object per input line.

## Architecture

- `tech_scan/cli.py`: argparse setup, scan orchestration, provider selection.
- `tech_scan/fetchers/`: requests fetcher, browser fetcher, redirect policy, headers, auto browser fallback heuristic.
- `tech_scan/cache.py`: SQLite cache for fetched resource observations and links.
- `tech_scan/providers/`: builtin rules, vendored `wappalyzergo` fingerprints, and optional user-supplied Wappalyzer JSON provider.
- `tech_scan/output.py`: human and JSONL output formatting.
- `tech_scan/models.py`: `FetchResult` and `Finding`.
- `tech_scan/normalize.py`: target normalization and HTTP fallback URL handling.

## Fetching And Cache Rules

The cache stores fetched resource observations, not provider results. Provider findings are recomputed from cached resources so the same response can be reused across provider sets.

Cache keys should depend on fetch identity:

- normalized target
- fetch mode
- proxy identity
- TLS trust identity (`--ca-bundle` or `--insecure`)
- fetch profile version

Do not key cache rows by provider set.

Fetch observations use normalized resource tables:

- `fetches` identifies the scan target and primary resource.
- `resources` stores documents, scripts, and future resource types with headers/body/error.
- `resource_links` links a parent resource to subresources by resource ID.

Requests mode fetches directly visible `<script src>` resources and links them to the document resource. Third-party scripts are allowed unless blocked by vendored EasyList/EasyPrivacy rules. Keep script fetching bounded and make script failures non-fatal to the main document fetch.

Redirects must stay on the same hostname. This prevents an app that redirects to a third-party SSO provider from being reported as the third-party site.

Fresh fetches run a default-on DNS/TCP sanity check before requests or browser mode. Bare domains check ports `80` and `443`; URL inputs check explicit ports when present, otherwise the scheme default. Cache hits bypass this check. Keep sanity failures uncached.

Browser mode uses one shared Playwright Chromium session per scan run. Keep Playwright sync API lifecycle on one thread. Use `CHROMIUM_PATH` when set, otherwise `/usr/bin/chromium` when executable, otherwise Playwright default lookup.

Browser mode loads vendored uBlock Origin Lite by default through a persistent Chromium context. Use `--no-browser-extension` when a raw browser session is needed. Because Chromium extensions require a persistent context, browser mode clears cookies between targets as best-effort isolation rather than creating a separate browser context per target when the extension is enabled.

Proxy/TLS behavior:

- `--proxy` accepts HTTP and SOCKS proxy URLs such as `http://127.0.0.1:8080` and `socks5h://127.0.0.1:1080`.
- `--ca-bundle` trusts a custom PEM bundle for requests mode and is passed to Chromium through well-known CA env vars as best effort. It defaults from `REQUESTS_CA_BUNDLE`, then `CURL_CA_BUNDLE`, then `SSL_CERT_FILE`.
- `--insecure` disables TLS verification in requests mode and uses Playwright `ignore_https_errors` in browser mode.
- Do not combine `--ca-bundle` and `--insecure`.

## Provider Rules

Keep builtin rules conservative and evidence-driven. Each finding should include:

- `name`
- `dimension`
- `provider`
- `confidence`
- `evidence`

`wappalyzergo` uses vendored `projectdiscovery/wappalyzergo` fingerprint JSON and must not shell out to subprocess wrappers. Keep the vendored upstream license and attribution beside the data. `wappalyzer_json` remains available for explicit user-supplied datasets via `--wappalyzer-data` or `WAPPALYZER_DATA`.

uBlock Origin Lite is vendored under fetcher data for browser mode. Keep its upstream license and attribution beside the extension files, and include it in package-data checks when packaging behavior changes.

## Development Commands

Run these before committing:

```bash
make check-uv
make clean
```

Common Makefile targets:

```bash
make test          # python -m unittest discover -s tests
make compile       # python -m compileall tech_scan tests
make check         # test + compile with the current Python
make test-uv       # uv run python -m unittest discover -s tests
make compile-uv    # uv run python -m compileall tech_scan tests
make check-uv      # test-uv + compile-uv
make clean         # remove pycache, build/dist, egg-info, and tool caches
make help          # uv run -m tech_scan --help
```

The Makefile defaults `UV_CACHE_DIR` to `/tmp/uv-cache`. Override it when needed:

```bash
UV_CACHE_DIR=/tmp/custom-uv-cache make check-uv
```

Proxy tests that open local sockets and browser smoke tests may require approval outside the sandbox. Browser smoke test:

```bash
echo 'https://example.com' | make smoke-browser
```

## Testing Guidance

Add or update tests for every behavior change. Prefer fake Playwright/browser objects for unit tests instead of requiring real browser binaries in the test suite.

Protect these behaviors with tests when touched:

- JSONL output stability.
- Human output includes all JSONL fields.
- Cache stores observations and is independent of provider set.
- Auto mode does not use browser for small static pages.
- Same-host redirect restriction.
- Browser session reuse and per-target browser context isolation.
- Proxy routing and TLS verification options.
- Browser resource capture and default uBlock Origin Lite loading.

## Commit Convention

The user explicitly requested that future project updates be committed. For each project update:

1. Implement the change.
2. Run relevant validation.
3. Remove generated bytecode/cache artifacts.
4. Commit the update unless the user explicitly says not to.

Use concise, behavior-focused commit messages.
