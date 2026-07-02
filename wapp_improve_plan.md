# WappalyzerGo Cached Detection Performance Plan

## Context

This note records profiling against a populated cache built from a 24-URL subset of
`tests/live_website_references.json`.

Benchmark inputs:

- Input list: `/tmp/tech_scan_live_subset_24.txt`
- Cache DB: `/tmp/tech_scan_live_bench_auto_cache.db`
- Cache contents: 35 fetch records, 28 `requests` and 7 `browser`
- Cached resources: 35 documents, 171 scripts, 12 redirects

The benchmark intentionally uses cached data so network, sanity checks, redirects,
and browser startup are out of the hot path.

## Observed Timings

CLI-level cached scans:

| Command shape | Time |
| --- | ---: |
| `--mode auto --cache only --provider builtin` | `2.14s` |
| `--mode auto --cache only --provider wappalyzergo` | `14.22s` |

Direct cached-observation profile:

| Step | Time |
| --- | ---: |
| `WappalyzerGoProvider()` init | `0.13s` |
| Cache JSON deserialize for 35 records | `0.10s` |
| `WappalyzerGoProvider.detect()` for 35 records | `12.44s` |

Conclusion: cached WappalyzerGo slowness is provider CPU work, not cache I/O,
SQLite, network, or scheduler overhead.

## Hot Spots

Direct timing by Wappalyzer pattern class:

| Pattern class | Time |
| --- | ---: |
| `js` | `6.70s` |
| `html` | `1.67s` |
| `dom` | `1.44s` |
| `scriptSrc` | `0.45s` |
| `headers`, `cookies`, `meta` | negligible |

Worst individual cached observations:

| Target | Source | Body bytes | Script resources | Script bytes | Detect time |
| --- | --- | ---: | ---: | ---: | ---: |
| `https://www.nike.com` | requests | 649,917 | 25 | 3,329,300 | `1.596s` |
| `https://www.nike.com/tw/` | requests | 649,917 | 25 | 3,329,300 | `1.586s` |
| `https://www.backmarket.com` | requests | 1,682,767 | 1 | 1,048,527 | `0.939s` |
| `https://www.paulsmith.com` | requests | 996,317 | 1 | 1,047,502 | `0.760s` |

Large captured JavaScript bodies are the dominant cost multiplier.

## Candidate Selection Problem

Current WappalyzerGo compilation stats from vendored fingerprints:

| Group | Count |
| --- | ---: |
| compiled apps | 1,330 |
| expensive-only apps | 721 |
| apps with `scriptSrc` patterns | 482 |
| apps with `html` patterns | 119 |
| apps with `js` patterns | 497 |
| apps with `dom` patterns | 240 |

Average candidate count per cached observation in the benchmark: about `936`
apps.

The current candidate selection is too broad:

- `_candidate_apps()` starts with every `expensive_only_app`.
- If the page has any script URL, it adds every app that has any `scriptSrc`
  fingerprint.
- `html`, `js`, and `dom` checks then run for hundreds of mostly implausible
  apps.

This means cached scans still perform live-style fingerprint evaluation against
megabytes of HTML and JavaScript.

## RE2 Compatibility

`google-re2` is installed in the project environment.

Fingerprint pattern count from `fingerprints_data.json`:

| Metric | Count |
| --- | ---: |
| total pattern occurrences, including empty patterns | 12,883 |
| empty pattern occurrences | 2,066 |
| non-empty pattern occurrences | 10,817 |
| unique non-empty patterns | 9,441 |

Compatibility by occurrence:

| Regex result | Count | Percent |
| --- | ---: | ---: |
| RE2-compatible | 10,417 | `96.30%` |
| Python `re` fallback only | 14 | `0.13%` |
| invalid as regex | 386 | `3.57%` |

Compatibility by unique non-empty pattern:

| Regex result | Count | Percent |
| --- | ---: | ---: |
| RE2-compatible | 9,050 | `95.86%` |
| Python `re` fallback only | 9 | `0.10%` |
| invalid as regex | 382 | `4.05%` |

Compatibility by fingerprint field:

| Field | Non-empty occurrences | RE2-compatible |
| --- | ---: | ---: |
| `headers` | 653 | `100.00%` |
| `cookies` | 23 | `100.00%` |
| `meta` | 765 | `100.00%` |
| `html` | 441 | `100.00%` |
| `scriptSrc` | 4,083 | `99.80%` |
| `js` | 3,280 | `88.23%` |
| `dom` | 176 | `96.59%` |
| `implies` | 1,396 | `100.00%` |

The Python `re` fallback cases are mostly negative lookahead/lookbehind
patterns, for example:

- `\.acquire\.io/(?!cobrowse)`
- `(?!angular\.io)\bangular.{0,32}\.js`
- `(?<!elo\.io)/cargo\.`
- `/sites/(?!(?:default|all)/).*/(?:files|themes|modules)/`

The `invalid` cases are concentrated in `js`. They appear to be Wappalyzer
JavaScript object/property maps that the current engine treats as ordinary text
patterns. They compile neither under RE2 nor Python `re`, then fall back to
substring matching of the stringified dictionary. That is probably both a
coverage bug and a performance bug.

## Regex Compilation Behavior

Regexes are compiled once per provider instance during `WappalyzerGoProvider()`
initialization.

They are not lazily compiled. The path is:

1. `WappalyzerGoProvider.__init__()`
2. `_WappalyzerFingerprintProvider.__init__()`
3. `_compile_apps()`
4. `_CompiledPattern.from_value()`
5. `compile_regex_or_none()`

`compile_regex_or_none()` tries RE2 first, then falls back to Python `re`, and
returns `None` if both reject the pattern. During matching:

- compiled RE2/Python patterns use `.search()`;
- empty patterns match immediately;
- patterns with no compiled regex use case-insensitive substring matching via
  `pattern.lower() in haystack.lower()`.

Implication: provider construction pays the compile cost up front, but cached
scan slowness is still dominated by repeated matching across too many candidate
apps and too-large haystacks.

## Recommended Optimization Plan

1. Fix Wappalyzer `js` object handling.
   - Do not treat dict-shaped `js` fingerprints as text regexes.
   - Compile them into JavaScript global/property checks when browser globals
     exist.
   - For static cached HTML/script bodies, either skip runtime-only JS property
     checks or convert only high-confidence string-valued checks that are
     semantically valid.

2. Narrow candidate selection before expensive matching.
   - Stop adding all `expensive_only_apps` unconditionally.
   - Keep cheap exact indexes for headers, cookies, and meta.
   - Add cheap prefilters for expensive groups before running regexes.

3. Build a literal/token prefilter for `html`, `js`, and `scriptSrc`.
   - Extract stable required literals from compatible regexes where possible.
   - Index apps by those literals.
   - Only run expensive regexes for apps whose literals are present in the
     relevant haystack.
   - Fall back conservatively for patterns where no useful literal can be
     extracted.

4. Improve `scriptSrc` indexing.
   - Many script URL rules are domain/path literals.
   - Index by hostname/path tokens so a page with any script does not make all
     482 `scriptSrc` apps candidates.

5. Reduce JavaScript body scans.
   - Avoid testing every `js` fingerprint against every captured script body.
   - Prefer script URL prefiltering first.
   - Consider per-resource body length caps only if accuracy impact is made
     explicit; the better first fix is candidate pruning.

6. Make DOM checks cheaper.
   - Index DOM selectors by simple tag/class/id tokens.
   - Only run `selectolax.css()` for selectors whose cheap selector token exists
     in the HTML.
   - Cache selector results within a detection run if multiple apps share a
     selector.

7. Consider provider-result caching only after pruning.
   - It would make repeated scans very fast, but it adds provider-versioning and
     invalidation complexity.
   - The current architecture intentionally caches fetch observations, not
     provider results, which is still the cleaner default.

## Expected Impact

The largest expected wins are:

1. Correctly handling or skipping dict-shaped `js` fingerprints.
2. Preventing all expensive-only apps from becoming candidates by default.
3. Preventing every script-bearing page from testing all `scriptSrc` apps.
4. Reducing repeated regex scans over megabytes of cached JavaScript.

RE2 is already doing useful work: about `96%` of non-empty Wappalyzer pattern
occurrences are RE2-compatible. The remaining performance issue is not regex
engine choice; it is the number of regex searches and the size of the haystacks.
