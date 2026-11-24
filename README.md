# xssforge

Context-aware XSS scanner with execution proof: precise HTML/JS context
classification, static DOM taint review, a headless-browser oracle, stored and
blind workflows, WAF-aware payload selection and multi-location injection.

> **Authorized testing only.** The scanner refuses to run without
> `--authorized`. Use it only on assets you own or have written permission to
> test. `lab.py` is a deliberately vulnerable local target for practice.

## Capabilities

- HTML/JS context tokenizer (state machine)
- Query/form/JSON/GraphQL/XML/multipart/path/fragment/header/cookie injection
- Browser execution proof (alert/confirm/prompt/DOM write hooks)
- Static DOM source->sink taint analysis
- Structural JS analysis (class fields, getters, params, exports)
- Evidence tiers + detection method (V/A/R/I)
- Library version -> targeted gadget payloads
- Mid-scan session-loss detection
- Built-in blind-XSS collaborator
- Interactsh auto-registration (no Go binary needed)
- Dynamic WAF-evasion mutation engine
- OpenAPI/Swagger endpoint import
- Login/session establishment
- Stored-XSS seeding + repeatable triggers + upload/attachment follow
- WAF fingerprint + curated bypass hints
- Diff/encoding analysis
- Raw HTTP request file input
- Output formats: JSON/JSONL/TOML/SARIF/HTML/MD
- Payload corpus: 22,496 static vectors + mutations

## Payload corpus

`payloads.py` combines five bundled sources and adds systematic generators:

- **PortSwigger XSS cheat sheet** vectors (`corpus/portswigger.txt`, 390 lines)
  plus a **2026-11-24 refresh** (`corpus/cheatsheet-2026.txt`, 202 additional
  vectors) and the **2026 update** (`corpus/2026-update.txt`, 110 vectors).
- **HexBrain / PayloadsAllTheThings XSS Injection** passages
  (`corpus/hexbrain.txt`, 157 lines; upstream MIT,
  swisskyrepo/PayloadsAllTheThings) and `corpus/extras-2026.txt`.
- Hand-curated context, mutation, CSP, JSONP, prototype-pollution, mXSS,
  WAF-bypass and encoding vectors.

On top of that, `_gen_*` builds tag/handler combinations, attribute breakers,
JS-string breakers, URL schemes and encoded variants at import time. Current
total: **22,496 category entries / 18,876 unique payload strings** (`python3 xssforge.py --stats`), configurable
per-context with `--payload-limit`. Every one of the 24 context categories
(HTML, double/single/unquoted attribute, script, URL, CSS, comment, SVG, mXSS,
CSP, polyglot, Angular, Vue, DOM, prototype pollution, postMessage, JSONP,
Markdown, file upload, RCDATA, WAF/firewall, encoding) ships **at least 300
unique vectors**.

### Encoders / decoders

58 encoders cover URL (single/double/triple/partial), HTML decimal/hex/padded/
named, JS `\u`/`\x`/octal, CSS escapes, comments, whitespace (tab/newline/CR/
form-feed), null, zero-width, fullwidth, UTF-7/UTF-16LE/BE, quoted-printable,
hex pairs, base64 (raw/eval/data-URI/script), `String.fromCharCode`, and more.
`lt-url`, `lt-url2` and `lt-html` encode only `<`, leaving the `alert('__M__')`
call executable when whole-payload encoding kills the proof. 15 decoders
(`lt-url`/`lt-html` included) reverse URL/HTML/JS-escape/base64/hex/
quoted-printable/UTF-16/fullwidth. Inspect or test them:

```bash
python3 xssforge.py --list-encoders
python3 xssforge.py --decode '%3Cimg%20src=x%20onerror=alert(1)%3E'
python3 xssforge.py -u 'https://target/?q=x' --encode all --authorized --browser
```

The mutation engine (`xf_mutate.py`) derives fresh WAF-evasion variants at scan
time from the strongest corpus vectors: tag/event case, HTML-comment splitting,
whitespace substitution (`/`, tab, newline, CR, form-feed), entity-encoded
calls, JS escapes, `window[...]` indirection and context-specific breakouts.
This is on by default (`--no-mutate` disables, `--mutate-base` / `--mutate-max`
tune depth).

### Every payload is bypass-capable

In addition to the mutation engine, **every corpus payload is automatically
paired with an obfuscated filter/WAF-bypass variant** at scan time
(`payloads.bypass_variants`). 18 techniques are available and chosen by context:
tag/event case, comment splitting, slash/tab/newline/CR/form-feed whitespace,
entity-encoded calls, JS `\u` escapes, `window[...]` indirection, string
concatenation (`window['ale'+'rt']`), angle-entity encoding, URL/double-URL
encoding, null bytes, leading whitespace and fullwidth. A composite `combo`
variant (tag case + `window['ale'+'rt']`) is tried first for HTML/attribute
contexts; `\u`/`window`/concat variants are tried first inside scripts.
Runtime placeholders (`__M__`, `__CB__`, ...) are preserved verbatim so the
canary always lands.

```bash
python3 xssforge.py -u 'https://target/?q=x' --authorized --browser        # 6 bypass/payload
python3 xssforge.py -u 'https://target/?q=x' --bypass-variants 12         # deeper
python3 xssforge.py -u 'https://target/?q=x' --max-candidates 0           # no candidate cap
python3 xssforge.py -u 'https://target/?q=x' --browser --first-hit         # stop at first reflection, escalate, print exploit
python3 xssforge.py -u 'https://target/?q=x' --no-bypass                  # originals only
```

Verified end-to-end against the lab: a filter that blocks `alert` is bypassed by
`"><sCrIpT>window['ale'+'rt'](...)</sCrIpT>` and confirmed executing in Chromium.

Regenerate the bundled source lists with:

```bash
python3 tools/build_corpus.py --ps /path/to/portswigger.html --patt /path/to/patt.md
# merge a saved hexbrainai.com XSS page too
python3 tools/build_corpus.py --hexbrain-html /path/to/hexbrain.html
```

## Install

Supported: Python 3.12+ on Linux (headless Chromium). CI verifies 3.12 and
3.14. Other POSIX systems may work but are not currently tested.

Clean install (reproducible, pinned):

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.lock
```

`requirements.txt` carries compatible version ranges for general use;
`requirements.lock` pins exact versions used by CI. Browser proof additionally
needs `selenium`, `chromedriver` and `chromium`/`chrome` on PATH (e.g.
`sudo apt-get install chromium chromium-driver` on Debian/Ubuntu). If any of
these are missing, the browser verifier reports `UNAVAILABLE` and **no finding
can be CONFIRMED** — it does not crash or silently claim verification.

## Usage

```bash
# reflected XSS with browser proof
python3 xssforge.py -u 'https://target/?q=test' --authorized --browser

# crawl the site and scan every discovered form/query
python3 xssforge.py -u 'https://target/' --authorized --crawl --browser --threads 12

# JSON API
python3 xssforge.py -u 'https://api.target/v1/search' -d '{"q":"x"}' -X POST \
  --authorized --browser

# headers, cookies, path, fragment
python3 xssforge.py -u 'https://target/' --inject-header X-Forwarded-For \
  --authorized --browser
python3 xssforge.py -u 'https://target/' -c 'session=abc' --inject-cookie session \
  --authorized --browser
python3 xssforge.py -u 'https://target/user/bob' --path --authorized --browser
python3 xssforge.py -u 'https://target/page' --dom-fuzz --browser --authorized

# Burp raw request
python3 xssforge.py --raw request.txt --scheme https --authorized --browser

# blind XSS with the built-in collaborator
python3 xssforge.py -u 'https://target/feedback' -d 'msg=x' \
  --oob-server 8888 --oob-host YOUR_PUBLIC_IP --authorized --browser

# blind XSS with interactsh (auto-registers; no Go binary needed)
python3 xssforge.py -u 'https://target/feedback' -d 'msg=x' \
  --interactsh --authorized --browser
# private interactsh server + token
python3 xssforge.py -u 'https://target/' --interactsh oast.internal \
  --interactsh-token TOKEN --authorized

# blind XSS with an external interactsh/collaborator URL
python3 xssforge.py -u 'https://target/' --blind https://xxxx.oast.fun --authorized

# import every documented API endpoint from OpenAPI/Swagger
python3 xssforge.py --openapi https://target/openapi.json --authorized --browser

# authenticate before crawling/scanning
python3 xssforge.py -u 'https://target/' --login-url https://target/login \
  --login-data 'user=me&pass=secret' --crawl --authorized --browser

# stored XSS: seed then render the trigger page
python3 xssforge.py -u 'https://target/comment' -d 'text=x' \
  --stored-url 'https://target/posts/1' --authorized --browser

# static DOM review + full report set
python3 xssforge.py -u 'https://target/app' --dom --authorized --report html,json,md

# local lab
python3 lab.py 8000
python3 xssforge.py -u 'http://127.0.0.1:8000/reflected?q=hi' --authorized --browser
```

Useful flags: `--all` (crawl + browser + DOM + fragment + encoders),
`--encode all`, `--payload-limit 0` (all corpus payloads),
`--evidence-max` (cap saved responses), `--no-mutate`, `--bypass-variants`,
`--no-bypass`, `--openapi`, `--interactsh`, `--login-url`,
`--threads`, `--delay`, `--proxy`, `--insecure`, `--json`, `--quiet`,
`--show-evidence`, `--stats`, `--coverage`.

### Troubleshooting common runs

- **Custom payload file seems ignored** — files passed with `--payloads` are
  tested first and are exempt from `--payload-limit`; only bundled corpus is
  limited.
- **Run takes forever** — `--threads` now parallelises properly (the delay is
  per thread). Keep `--payload-limit` sane, or use `--all` which still bounds
  each phase.
- **Reflected but not `CONFIRMED`** — add `--browser`; without the headless
  oracle the tool reports `LIKELY`/`REFLECTED` only.
- **Nothing reflected** — the value may be read by JavaScript. Use
  `--dom-fuzz --browser` (or `--all`) to test client-side sinks and fragments.
- **WAF blocks the payloads** — the report prints how many requests were
  blocked. Add `--encode all` (or `--all`); the tool falls back to encoded and
  obfuscated variants automatically when it sees blocking.
- **Other XSS types** — stored (`--stored-url`), blind (`--oob-server` /
  `--interactsh` / `--blind`), DOM (`--dom`, `--dom-fuzz`), mXSS/CSP/polyglot
  (payload sets); see `--coverage`.


## How detection works

1. A unique canary is sent to each injection point.
2. If it reflects, `xf_context` walks an HTML5-flavoured state machine to the
   reflection offset and reports the exact context (`attr_dq`, `script_string`,
   `url`, `comment`, `rcdata`, `svg`, ...), tag and attribute.
3. Context-specific payloads are filled with the canary, sent, and analysed for
   raw / encoded / mutated reflection (`xf_context.response_encoding_hint`).
4. High-confidence vectors are verified in headless Chromium with `alert`,
   `confirm`, `prompt`, `print`, `console.log`, `innerHTML`,
   `document.write`, `insertAdjacentHTML` and `eval` instrumentation. Elements
   carrying the canary are focused/clicked/dispatched so event-handler and
   `javascript:` URL vectors are actually exercised. A trusted WebDriver click
   is also dispatched on canary-bearing links because Chrome rejects synthetic
   `el.click()` for `javascript:` URLs without user activation.
5. Findings are graded V/A/R/I (verified, actionable, reflection,
   informational) with a `detection_method` and a human `confidence_reason`;
   JSON, JSONL, TOML, SARIF, HTML and Markdown reports all carry the grade.
   `--only-poc` keeps only V/A evidence.

Blind payloads are delivered to non-reflecting points and matched against the
built-in collaborator, an external callback URL, or a live interactsh session.
Stored payloads are seeded into forms/JSON bodies (content *and* filename for
uploads) and every `--sxss-url` trigger page is rendered in the browser;
download/attachment responses are ignored because they never execute.

The structural DOM pass tokenizes JS (comments/strings blanked), then tracks
sources through class fields, getters, parameter defaults, destructuring and
module exports before matching sinks such as `innerHTML`, `eval`, jQuery
`html()/append()/attr()/prop()/wrap()`, `document.write` and
`document.currentScript.src`. Detected libraries (jQuery, AngularJS, DOMPurify,
Bootstrap, ...) add version-gated gadget vectors. GraphQL `variables` and
XML/SOAP text/attributes are treated as first-class injection points.
`--ai-fallback` is an opt-in LLM payload generator (disabled without
`XSSFORGE_AI_KEY`).

## Interactsh

`--interactsh` implements the interactsh register/poll protocol directly:
RSA-2048 key pair, `POST /register`, per-vector callback nonce, and
AES-CTR + RSA-OAEP(SHA-256) decryption of `/poll` results. Only the public key
leaves the host. It falls back across `oast.fun`, `oast.pro`, `oast.live`,
`oast.site`, `oast.online` and `oast.me`, and supports private servers with
`--interactsh-token`.

## Testing

```bash
python3 -m pytest tests/ -q
```

150 tests: offline unit tests, local-lab browser/DOM integration tests and a slow-target reliability test. The
integration suite starts the bundled deliberately-vulnerable `lab.py` on an
ephemeral 127.0.0.1 port and self-skips if browser dependencies are missing.
It asserts that known-executing fixtures become CONFIRMED and that escaped,
plain-text and negative fixtures never do. CI publishes JUnit XML and pytest
logs as artifacts. The versioned fixture list is `benchmark/cases.json`.

Scope: run tests and scans only against the bundled lab, intentionally
vulnerable applications, or systems you have explicit written authorization to
test. The scanner requires `--authorized` for live targets.

## Verification states

Findings carry an explicit `verification` field:

- `REFLECTION` / `CANDIDATE` / `LIKELY` — echo or context evidence only;
  execution is **not** established.
- `CONFIRMED` — a harmless per-scan canary demonstrably executed in an isolated
  headless browser; includes `browser_evidence` with evidence type, test ID,
  UTC timestamp, browser version and automation version.
- `CALLBACK_OBSERVED` — out-of-band callback only; not browser confirmation.
- `NOT_VERIFIED` — verification could not be performed or produced no proof;
  `verification_reason` explains why.

The scan-level browser oracle state is recorded in report metadata under
`meta.browser` (`DISABLED`, `UNAVAILABLE`, `READY`, `COMPLETED`, `TIMED_OUT`,
`FAILED`) together with verifier counts. Reports also include scan start/end,
duration, request count, requests/second and peak memory under `meta.scan`.
`Ctrl-C` sets a shared stop flag so in-flight work finishes cleanly; transport
and 502/503/504 retries are bounded in one place and logged.

## DOM, stored and blind evidence

DOM findings carry a `flow` string (`source -> variable -> sink`), `line`,
`column`, `script` URL, `snippet` and `analysis: static-source-to-sink`. With
`--dom --browser`, controllable sources (`location.hash`, `location.search`
and URL-parsing APIs) get an in-browser canary attempt; only a real execution
sets `CONFIRMED` plus `browser_evidence`. Sources that cannot be driven from the
browser URL (cookies, storage, postMessage, referrer) stay `NOT_VERIFIED` with a
reason. Static analysis alone is never a confirmed finding; minified/obfuscated
JS, framework internals and asynchronous flows remain known blind spots.

Stored tests use per-trigger random test IDs (`test_id`). A disposable record is
cleaned up only when the operator supplies `--stored-cleanup-url`; the URL,
HTTP result and cleanup status are recorded per result. No cleanup endpoint is
guessed. Out-of-band traffic happens only with explicit `--blind`,
`--oob-server` or `--interactsh` configuration; `meta.oob` records the provider,
and blind hits are labeled `CALLBACK_OBSERVED`, never browser-confirmed.
Each blind hit is normalized into `callback_evidence` (provider, per-scan token,
UTC hit times, method/path/client) and rendered in the JSON, Markdown and HTML
reports; the raw collaborator/interactsh records remain in `blind_hits`.

## Layout

```
xssforge.py        CLI + orchestration + scoring
payloads.py        corpus loader, generators, encoders, context map
xf_context.py      HTML/JS context tokenizer
xf_points.py       injection points + request/curl construction + raw HTTP
xf_crawl.py        same-origin crawler (links, forms, JS endpoints, sitemap)
xf_browser.py      headless Chromium pool + execution instrumentation
xf_dom.py          static DOM source->sink taint analysis
xf_ast.py          tokenizer/scope-aware JS structural taint analysis
xf_evidence.py     V/A/R/I grading + detection method
xf_session.py      mid-scan auth/session-loss watcher
xf_gadget.py       library version -> gadget payload mapping
xf_ai.py           optional LLM payload fallback
xf_hunt.py         methodology layer: recon signals -> prioritized hunt plan
xf_oob.py          built-in HTTP collaborator
xf_interactsh.py   interactsh register/poll client (RSA + AES-CTR)
xf_mutate.py       on-the-fly WAF-evasion mutation engine
xf_openapi.py      OpenAPI/Swagger -> injection points
xf_waf.py          WAF fingerprint + block detection
xf_report.py       console/JSON/HTML/Markdown reporting
tests/test_core.py offline unit tests
lab.py             local vulnerable practice lab
tools/build_corpus.py  regenerate bundled payload lists
```

Always validate a finding manually before reporting it. A scanner produces
candidates; proof is the job.

## Methodology layer (`--hunt`)

`--hunt` turns passive recon signals into a prioritized plan: outdated
DOMPurify, postMessage handlers with weak origin checks, OAuth
`redirect_uri`/`returnTo` reflection, upload/stored surfaces, markdown/rich-text
renderers, RSC/React, LLM output rendering, prototype-pollution sources, CSP and
dangerous JS sinks. It is read-only and is enabled automatically by `--full`.
The plan is stored in `meta.hunt` in the JSON report.

## Publishing to GitHub

- Keep the `--authorized` gate and the "authorized testing only" notice.
- Add a `LICENSE`, a `SECURITY.md` with a disclosure contact, and a short
  `CONTRIBUTING.md` if you want outside fixes.
- Do not commit cookies, session tokens, Burp projects, captured responses,
  screenshots, or victim data from tests (check `xssforge-out/` and `/tmp`).
- Use sanitized local-lab examples (DVWA / `lab.py`) in screenshots and docs.
- Keep proof-first grading (V/A/R/I + `detection_method`) and the offline test
  suite in CI; never merge a change that reduces test coverage.
- Label optional network features (`--ai-fallback`, `--web-refresh`,
  `--interactsh`) clearly so users know what leaves their machine.
