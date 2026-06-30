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
```

Fetch modes:

- `requests`: browser-like HTTP request headers, no JavaScript execution.
- `browser`: Playwright Chromium rendering.
- `auto`: requests first, browser only for likely missed content: request errors, `401`/`403`/`429`/`503`, no useful response, explicit JavaScript-required text, or sparse SPA shells with no useful findings.

Output modes:

- `human`: default, multi-line colorized output.
- `jsonl`: one stable JSON object per scanned URL. Bare domains scan both HTTP and HTTPS and therefore emit two objects.

Human output must include all fields present in JSONL.

Raw observations:

- Results may include top-level `observations`, currently non-scoring raw header context for signature-relevant headers such as `Server`, `X-Powered-By`, `Via`, CDN/WAF headers, and selected platform/cache headers.
- Observations are not technologies, findings, confidence, or evidence. They must not affect provider scoring or summaries.
- Suppress a raw header observation when the same exact `Header: value` string is already used as source-backed finding evidence.

Diagnostics:

- `--verbosity 0`: default, short error messages only.
- `--verbosity 1`: adds fetcher-switch reasons and redirect traces on stderr.
- `--verbosity 2`: includes stack traces for live top-level fetch failures and stderr exception diagnostics.
- `--verbosity 3`: adds detailed cache, fetch, browser, resource, provider, and timing logs on stderr.
- Keep verbose diagnostics on stderr so JSONL stdout remains one machine-readable object per scanned URL.

## Architecture

- `tech_scan/cli.py`: argparse setup, stdin/stdout handling, validation, and process-level browser-session lifecycle.
- `tech_scan/scanner.py`: scan orchestration for target expansion, cache lookup/write, sanity checks, fetcher execution, auto browser fallback, provider execution, and result assembly.
- `tech_scan/cli_config.py`: CLI-derived TLS, CA bundle, Chromium, and cache identity helpers.
- `tech_scan/fetchers/`: requests fetcher, browser fetcher, headers, resource capture, and auto browser fallback heuristic.
- `tech_scan/cache.py`: SQLite cache for fetched resource observations and links.
- `tech_scan/providers/`: builtin rules and vendored `wappalyzergo` fingerprints.
- `tech_scan/providers/wappalyzer_engine.py`: internal Wappalyzer fingerprint engine used by the vendored `wappalyzergo` provider; not a public provider.
- `tech_scan/output.py`: human and JSONL output formatting.
- `tech_scan/models.py`: `FetchResult` and `Finding`.
- `tech_scan/normalize.py`: target expansion from stdin input into concrete HTTP/HTTPS URL candidates.
- `tech_scan/html_extract.py`: shared lightweight HTML extraction for scripts, meta tags, and URL-bearing attributes.
- `tech_scan/url_policy.py`: shared same-host and redirect URL helpers.

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

Fresh fetches run a default-on DNS/TCP sanity check before requests or browser mode. Bare domains expand to `http://` and `https://` scans; each concrete URL checks its explicit port when present, otherwise `80` for HTTP or `443` for HTTPS. Cache hits bypass this check. Keep sanity failures uncached.

Fetchers receive one concrete URL and must fetch only that URL. Do not reintroduce protocol fallback inside fetchers; all HTTP/HTTPS expansion belongs before cache, sanity, and fetch in the scanner/normalization layer.

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

`wappalyzergo` uses vendored `projectdiscovery/wappalyzergo` fingerprint JSON and must not shell out to subprocess wrappers. Keep the vendored upstream license and attribution beside the data. Do not expose user-supplied Wappalyzer JSON as a selectable provider; public provider choices are only `builtin`, `wappalyzergo`, and `all`.

Builtin may borrow high-signal Wappalyzer-style signatures only when they fit existing dimensions and can produce clear evidence. Keep ambiguous or broad coverage in `wappalyzergo`; do not bulk-import fingerprints or add broad CMS/payment/analytics/auth/ad reporting to builtin.

Do not add public imports for internal provider or fetcher helper APIs in package `__init__.py` files. Import implementation helpers from their owning modules, such as `tech_scan.url_policy`, `tech_scan.html_extract`, `tech_scan.fetchers.auto`, or `tech_scan.providers.wappalyzer_engine`.

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
- Raw observations stay separate from technologies and do not affect scoring.
- Cache stores fetch observations and is independent of provider set.
- Scanner orchestration preserves cache, sanity, fetcher, provider, and auto-fallback behavior.
- Auto mode does not use browser for small static pages.
- Same-host redirect restriction.
- Shared HTML extraction and URL policy helpers remain deterministic.
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
