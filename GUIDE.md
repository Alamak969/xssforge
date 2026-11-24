# xssforge — Detailed Usage Guide

Context-aware XSS scanner with execution proof. This guide explains every
feature and flag, with examples.

> Authorized testing only. The tool refuses to run without `--authorized`.
> Only test systems you own or have written permission to test.

---

## 1. Install and first run

```bash
cd ~/Desktop/xssforge
pip install -r requirements.txt
# browser proof needs Chromium + chromedriver on PATH
python3 lab.py 8000            # local vulnerable practice lab (127.0.0.1 only)
python3 xssforge.py -u 'http://127.0.0.1:8000/reflected?q=hi' --authorized --browser
```

Quick health checks:

```bash
python3 xssforge.py --stats        # corpus size per category
python3 xssforge.py --coverage     # which XSS types are automated vs manual
python3 xssforge.py --list-encoders
```

### Command advisor
Not sure which flags to use? Ask the tool — no requests are sent:

```bash
python3 xssforge.py --recommend -u 'https://target/search?q=x'
python3 xssforge.py --recommend -u 'https://target/'
python3 xssforge.py --recommend -u 'https://alf.nu/alert1?world=alert&level=alert0'
```

`--recommend` now sends **one lightweight GET** to the target (a passive
baseline check — no payload scan) and prints a `[TARGET PROBE]` summary: status,
WAF fingerprint, whether a canary is reflected, login page, forms, DOM sinks and
CSP header. Commands are then tailored to those observed facts, e.g. canary
reflected → reflected workflow, login page → `-c SESSION=...`, DOM sinks →
`--dom --dom-fuzz`, WAF → `--proxy-file`/`--delay`.

A minimal `python3 xssforge.py -u '<URL>'` also performs that one-GET probe and
prints a one-line tip before the authorization notice. After a scan with no
findings the tool prints suggested next commands.

---

## 2. How the scanner works (mental model)

1. **Injection points** are built from your URL/body/headers/cookies/path/fragment.
2. For each point a unique canary (`zq<hex>`) is sent once.
3. If the canary is reflected, an HTML/JS state machine classifies the exact
   context (`html`, `attr_dq`, `script_string`, `url`, `svg`, ...).
4. Context-specific payloads are sent; reflection and encoding are analysed.
5. Candidates are scored; `--browser` runs headless Chromium to prove execution
   (`alert`, `confirm`, DOM sinks, `document.write`, `innerHTML`, `eval`, ...).
6. If a point never reflects, blind payloads are delivered to OOB callbacks.
7. Reports are written to `--output-dir`.

Status meanings in the report:

| Status | Confidence | Meaning |
|---|---|---|
| `CONFIRMED` | 95 | Browser proved execution (alert/DOM sink hit with canary) |
| `LIKELY` | 55-90 | Executable-looking reflection; not yet proven |
| `REFLECTED` | 40-54 | Input reflected but not clearly executable in context |
| `NO` | - | Not reflected / blocked / no candidate |

Reports are candidates. Always validate manually before reporting.

---

## 3. Target and request flags

### `-u, --url`
Target URL.

```bash
python3 xssforge.py -u 'https://target/search?q=hi' --authorized
```

### `-p, --param`
Only test these parameter names (repeatable). Useful to focus one input.

```bash
python3 xssforge.py -u 'https://target/?a=1&b=2' -p a --authorized
```

### `-d, --data` + `-X, --method`
Request body. JSON is detected by leading `{`/`[` and split into nested JSON
paths. `key=value&...` becomes form fields. Multipart is parsed if you pass a
multipart body and content type.

```bash
# form POST
python3 xssforge.py -u 'https://target/comment' -d 'text=x&name=y' -X POST --authorized

# JSON POST
python3 xssforge.py -u 'https://target/api/search' -d '{"q":"x","page":1}' -X POST --authorized
```

### `-H, --header`
Extra request header (repeatable).

```bash
python3 xssforge.py -u 'https://target/' -H 'Authorization: Bearer TOKEN' --authorized
```

### `-c, --cookie` / `--cookie-file`
Raw `Cookie:` header string, or a Netscape `cookies.txt` jar.

```bash
python3 xssforge.py -u 'https://target/' -c 'session=abc; role=user' --authorized
python3 xssforge.py -u 'https://target/' --cookie-file cookies.txt --authorized
```

### `--login-url`, `--login-data`, `--login-json`, `--login-method`
Perform a login once per session so crawling and scanning stay authenticated.

```bash
python3 xssforge.py -u 'https://target/' --crawl \
  --login-url 'https://target/login' \
  --login-data 'user=me&pass=secret' \
  --authorized --browser
```

### `--raw` + `--scheme`
Load a Burp-style raw HTTP request file. Query, body, headers and cookies are
turned into injection points.

```bash
python3 xssforge.py --raw request.txt --scheme https --authorized --browser
```

---

## 4. Injection locations

The tool injects into every location it can derive:

- **query** — URL parameters
- **form** — urlencoded body fields
- **json** — nested JSON body paths (type-preserving where possible)
- **multipart** — multipart form fields
- **header** — headers named with `--inject-header`
- **cookie** — cookies named with `--inject-cookie` (needs `-c`/`--raw`)
- **path** — last URL path segment (`--path`)
- **fragment** — URL fragment, client-side only (`--fragment`)

```bash
# header injection
python3 xssforge.py -u 'https://target/' --inject-header X-Forwarded-For --authorized

# cookie injection
python3 xssforge.py -u 'https://target/' -c 'session=abc' \
  --inject-cookie session --authorized

# path and fragment
python3 xssforge.py -u 'https://target/user/name' --path --authorized
python3 xssforge.py -u 'https://target/page#start' --fragment --browser --authorized
```

---

## 5. Discovery

### `--crawl` and friends
Same-origin crawler finds links and forms. It then creates points for every
query parameter and every form field.

```bash
python3 xssforge.py -u 'https://target/' --crawl \
  --crawl-depth 2 --crawl-max-pages 50 \
  --authorized --threads 12
```

- `--crawl-depth` link depth (default 2)
- `--crawl-max-pages` page budget (default 50)
- `--crawl-subdomains` allow in-scope subdomains

### `--openapi`
Import an OpenAPI/Swagger spec (URL or file). Query, path, JSON and form fields
become points.

```bash
python3 xssforge.py --openapi https://target/openapi.json -u 'https://target/' --authorized
```

### `--dom`
Static source-to-sink taint analysis across inline and external JS for the
target URL and discovered point URLs. Finds `location.hash`, `location.search`,
`document.referrer`, `postMessage`, storage, etc. flowing into `innerHTML`,
`document.write`, `eval`, `setAttribute`, etc.

```bash
python3 xssforge.py -u 'https://target/app' --dom --authorized
```

### `--dom-fuzz`
Browser-test client-side sinks and URL fragments with DOM payloads. Also acts as
a fallback when the server does not reflect input (SPA/client-side rendering).

```bash
python3 xssforge.py -u 'https://target/app' --dom-fuzz --browser --authorized
```

---

## 6. Execution proof: the browser oracle

### `--browser`
Runs headless Chromium and instruments `alert/confirm/prompt/print`,
`console.log`, `innerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, and
window errors. It also focuses/clicks/dispatches events on elements carrying the
canary so event-handler and `javascript:` vectors fire.

```bash
python3 xssforge.py -u 'https://target/?q=x' --browser --authorized
```

- `--browser-pool` number of simultaneous browsers (default 2)
- `--browser-max` max browser verifications per scan (default 4)
- `--browser-wait` seconds to keep collecting proof after navigation (default 3.5).
  Raise it (e.g. 10) for async/`setTimeout` payloads or slow pages.

Without `--browser`, results are only `LIKELY`/`REFLECTED` — never `CONFIRMED`.

### Browser blocked by WAF/bot protection
The browser oracle detects challenge pages ("Just a moment...", "Checking your
browser", CAPTCHA, "Access denied", Cloudflare/Interstitial markers) and reports:

```
[BROWSER BLOCKED] just a moment
! browser proof was BLOCKED on 3 verification(s) — WAF/bot challenge detected
```

Each affected candidate is labelled `BROWSER BLOCKED: <reason>` and the final
exploit block says `execution NOT proven` instead of claiming a kill. This
prevents a challenge page from being mistaken for a failed XSS payload.

Workarounds: pass real `--cookie`/`--header` values, use `--proxy`, reduce
`--browser-pool` / raise `--delay`, or use a real (non-headless) session and
validate the printed payload manually.

### Quote-escaping targets (PHP addslashes / magic quotes)
If the browser reports `SCRIPT EXECUTED BUT MANGLED (SyntaxError)`, the target
backslash-escaped the quotes in `alert('TOKEN')`. The script did run — the
payload was corrupted. Use a quote-less canary:

```bash
python3 xssforge.py -u 'URL?id=x' --authorized --browser --first-hit \
  --canary-style regex        # alert(/TOKEN/) instead of alert('TOKEN')
```

`--canary-style` accepts `quoted` (default), `ident` (`alert(TOKEN)`), `regex`
(`alert(/TOKEN/)`) and `template` (`` alert(`TOKEN`) ``). The tool also adds
`noquote-*` encoders/bypass variants and tries them first during escalation.
The exploit block prints both the template and the **exact bytes sent**.

---

## 7. Payloads

### `--payloads FILE`
Add your own payload file(s) (one payload per line, repeatable). These are
tested **first** and are **not** limited by `--payload-limit`.

```bash
python3 xssforge.py -u 'https://target/?q=x' --payloads mypayloads.txt --authorized
```

### `--payload-limit N`
Limit bundled corpus payloads per context (default 300). `0` = all corpus
payloads (can be very slow: the corpus is 18,501).

### `--list-payloads`, `--stats`
Dump the corpus / per-category counts.

```bash
python3 xssforge.py --stats
python3 xssforge.py --list-payloads | head
```

---

## 8. WAF / filter evasion

WAF fingerprinting runs automatically. When blocking is detected, the report
prints how many payloads were blocked and the tool automatically tries encoded
variants.

### `--mutate` / `--no-mutate` (default ON)
Derive fresh variants from promising corpus payloads: case mixing, comment
splitting, whitespace/`/` tricks, entity/unicode/JS escaping, tag duplication,
URL-scheme obfuscation, etc.

- `--mutate-base N` corpus payloads to mutate per point (default 4)
- `--mutate-max N` max variants per base (default 24)

### `--auto` — view-source style filter fingerprinting
Before sending any real payload, `--auto` probes each injection point with small
tokens (`<`, `>`, `/`, `'`, `"`, `=`, `alert`, `script`, `onerror`, `javascript:`,
`<svg`, ...) and classifies each one as **ALLOWED**, **BLOCKED**, **REMOVED** or
**ESCAPED** (with the exact transformation, e.g. `&#039;`, `%3C`, `\'`).

```bash
python3 xssforge.py -u 'https://target/?q=x' --authorized --browser --auto --first-hit
```

Consecutive boolean switches may be joined into one token — the parser splits
`--authorized-browser--auto` into `--authorized --browser --auto`, so the same
scan can be written as:

```bash
python3 xssforge.py -u 'https://target/?q=x' --authorized-browser--auto --first-hit
```

`--auto` is a one-shot switch: unless told otherwise it also enables browser
proof and first-hit escalation, and the filter fingerprint runs **before** the
WAF baseline and before any real payload is sent. Use `--no-browser` and/or
`--no-first-hit` to keep those off.

It then prints a `[FILTER PROFILE]` and automatically:
- picks encoders that avoid the blocked constructs (`html-hex`, `url`,
  `noquote-regex`, `fromcharcode`, ...),
- switches the canary to `alert(/TOKEN/)` when quotes are filtered,
- skips the payload phase entirely with a clear message if the input is **not
  reflected** (so no reflected/stored XSS is reachable there).

Use `--auto-probes N` to limit probes and `--auto-points N` to limit points.
To probe only specific characters (e.g. just `<`, `/`, `>`), use:

```bash
python3 xssforge.py -u 'URL?q=x' --authorized --auto \
  --probe-chars '<,>,/'
```

`\t`, `\n`, `\s` and `\0` are accepted for whitespace/NUL probes.
The profile is also saved in the JSON report under `meta.filter_profile`.

### `--raw-inject` — literal bytes in query values
Some endpoints only reflect raw quotes/angles; `requests` and browsers normally
percent-encode them before sending. With `--raw-inject`, query values are sent
as literal bytes and browser proof loads the unmodified response body, so this
class of reflection is testable:

```bash
python3 xssforge.py -u 'https://target/details.php?id=1' \
  --authorized --raw-inject --browser --first-hit
```

Because the payload must travel as raw bytes, a normal clickable browser URL
cannot reproduce it — use the curl reproducer from `[EXPLOIT PAYLOAD]`.

### `--deep-bypass` — keep generating variants until one works
When the normal passes fail, `--deep-bypass` uses the `--auto` filter profile to
lazily generate an effectively unlimited stream of variants from the first
reflected payload: every encoder, bypass technique, mutation, case/whitespace
trick, chained encoder-over-bypass transformations, and further iterative
expansion. Variants that avoid raw blocked tokens — and encoders selected by
the profile — are tried first. Generation is lazy, so memory stays bounded.

```bash
python3 xssforge.py -u 'URL?q=x' --authorized --auto --browser \
  --deep-bypass --bypass-max 300 --bypass-time 600
```

- Before generating, the tool selects up to `--seed-payloads N` (default 20)
  **web-derived corpus payloads** matched to the attack type (reflected / stored
  / DOM / blind / header), the injection context and the filter profile. Those
  are tested first; only if none work does generation start.
- `--web-refresh` fetches current public payload sources (PayloadsAllTheThings,
  OWASP filter-evasion sheet) at runtime and adds them to the seed pool.
- `--bypass-seed PAYLOAD` overrides the automatically chosen generator seed.

To inspect generated payloads **without sending any requests**:
```bash
python3 xssforge.py --dump-generated generated.txt --dump-count 200 \
  --bypass-seed "<script>alert('__M__')</script>"
```
With `-u` supplied, `--dump-generated` first performs the same passive web
analysis as `--recommend` and prints `[WEB ANALYSIS]`. It then pulls the most
likely payloads from the web-derived corpus for the inferred attack type
(`reflected` / `dom` / `stored` / `challenge` / `login`) and generates
**analysis-driven** variants: WAF fingerprints bias toward obfuscation, blocked
quotes toward quote-less canaries, blocked `alert` toward the detection ladder,
CSP toward gadget/bypass encoders, and challenge sites toward literal
`alert(1)` win payloads. The file contains the "possible win payloads" printed
below the analysis summary.

The generator yields **827 unique variants** for the default seed (54 encoders,
20 bypass techniques, 24 mutations, case/whitespace tricks, chained and
iterative expansion). In a scan, `--bypass-max` decides how many are actually
tested.
- `--bypass-max N` (default 100) and `--bypass-time SEC` (default 300) bound the
  loop; raise them for a longer brute-force.
- Each confirmed hit is reported as `[EXPLOIT][DEEP]` and included in the
  `[EXPLOIT PAYLOAD]` block with its screenshot and curl reproducer.

Use this only on targets you are authorized to test — it can send many requests.

### Detection-mechanism ladder (when `alert` is blocked)
A negative `alert` result is never treated as "no XSS". `--auto` probes
`alert`, `prompt`, `confirm`, `print`, `console.log`, `document.title` and
`fetch`. If `alert` is removed/blocked, the profile automatically puts these
proof primitives first in the escalation ladder:

```
alt-prompt, alt-confirm, alt-print, alt-console,
call-template, call-concat, call-atob, call-constructor,
call-unicode, call-throw, call-title
```

Browser hooks record `prompt`/`confirm`/`print`/`console.log`, `document.title`
writes and `fetch`/`sendBeacon` URLs carrying the canary, plus uncaught errors
(so `window.onerror=alert;throw TOKEN` works). This follows the 2026 WAF-bypass
guidance: rotate the detection mechanism instead of concluding from `alert`
alone. The browser budget is reset before escalation so the ladder is actually
verified rather than skipped.

### `--bypass` / `--no-bypass` (default ON)
Generate curated filter-bypass variants (combo, entity-call, window-call,
concat-call, fullwidth, null-byte, ...).

- `--bypass-variants N` variants per base (default 6)

### `--max-candidates N`
Cap the number of candidates kept per injection point (default 500, `0` = unlimited).
Older builds silently stopped after 25 candidates, which also prevented the
mutation and encoder passes from running. Raise it for a full corpus sweep,
lower it if reports get too large.

### `--encode LIST`
Encode payloads. `all` = every encoder. Useful encoders: `url`, `url2`, `url3`,
`html-dec`, `html-hex`, `js-unicode`, `js-hex`, `fullwidth`, `utf7`, `zwsp`,
`b64doc`, `fromcharcode`, `reverse`.

```bash
python3 xssforge.py -u 'https://target/?q=x' --encode all --authorized
python3 xssforge.py -u 'https://target/?q=x' --encode url,html-hex,fullwidth --authorized
```

- `--encode-max N` max base payloads to encode (default 4)
- Encoded variants are only reported when the server actually decoded them or
  the browser proves execution (prevents false positives).
- When WAF blocking is detected, a sensible encoder set is tried automatically
  even without `--encode`.

### `--decode STRING`
Try every decoder on a string and print results (offline helper).

```bash
python3 xssforge.py --decode '%3Csvg%20onload%3Dalert(1)%3E'
```

### `--list-encoders`
List all encoders, decoders and bypass techniques.

---

## 9. Blind XSS (OOB callbacks)

### `--interactsh [SERVER]`
Auto-register with an interactsh server (default `oast.fun`). This is the
easiest option if the target can reach the internet. Use `--interactsh-token`
for a private server.

```bash
python3 xssforge.py -u 'https://target/feedback' -d 'msg=x' \
  --interactsh --authorized --browser
```

### `--oob-server [PORT]`, `--oob-host`, `--oob-wait`
Start a built-in HTTP collaborator. `--oob-host` must be a public IP/host the
target can reach (NAT/port-forward or VPS).

```bash
python3 xssforge.py -u 'https://target/feedback' -d 'msg=x' \
  --oob-server 8888 --oob-host YOUR_PUBLIC_IP --oob-wait 20 \
  --authorized
```

### `--blind URL`
Use an external callback base URL (your own collaborator).

Blind payloads (script/img/svg/fetch/beacon/keylog/cookie-exfil, etc.) are
delivered to every non-confirmed point. Hits show as `BLIND` in the report.

---

## 10. Stored XSS

### `--stored-url` / `--sxss-url`
Seeds token-bearing payloads (including SVG/HTML upload documents and
quote-breaking filenames) into every non-fragment point, then loads the trigger
URL and checks reflection and browser execution. `--sxss-url` is repeatable, so
profile pages, admin queues and upload-render endpoints can all be followed in
one run. Responses served as downloads (`Content-Disposition: attachment`,
binary content types) are skipped because they never execute.

```bash
python3 xssforge.py -u 'https://target/comment' -d 'text=x' -X POST \
  --sxss-url 'https://target/posts/1' \
  --sxss-url 'https://target/admin/queue' \
  --browser --authorized
```

If the render page needs auth, add `--login-url`/`--cookie`. The scanner also
watches the authenticated page during the run and prints
`SESSION LOST mid-scan` (with the reason) if the login form reappears, so
"not reflected" results from an expired session are not trusted. For a payload
that only fires in another user's browser (admin panel), also add
`--interactsh`.

### `--dom-form SELECTOR` — client-side / DOM-stored XSS
Some apps store input in `localStorage`/`sessionStorage` via their own JS submit
handler (e.g. Google XSS Game level 2). `--stored-url` cannot reach those because
nothing is sent to the server. Instead, give the tool a CSS selector for the
on-page input/textarea: it fills it with canary payloads, clicks the form's own
submit control, and verifies execution in the browser.

```bash
python3 xssforge.py -u 'https://target/page' --authorized --browser \
  --dom-form '#post-content'
```

`--dom-form-submit 'CSS_SELECTOR'` overrides the submit button (default: the
submit inside the same form). Confirmations include a screenshot and the exact
delivered payload, and are included in `[EXPLOIT PAYLOAD]`.

---

## 11. Performance and network

| Flag | Default | Purpose |
|---|---|---|
| `--threads` | 8 | concurrent workers (delay is per worker now) |
| `--delay` | 0.10 | seconds per request, per thread |
| `--timeout` | 15 | request timeout (seconds) |
| `--retries` | 1 | retries for GET/HEAD/OPTIONS on 502/503/504 |
| `--proxy` | - | HTTP(S) proxy (e.g. Burp `http://127.0.0.1:8080`) |
| `--insecure` | off | skip TLS verification |
| `--user-agent` | Chrome UA | override User-Agent |
| `--retries` | 3 | retry transient network errors / 502-504 |
| `--timeout` | 15 | per-request timeout — raise to 90 for very slow hosts |
| `--oob-wait` | 8 | seconds to poll blind/OOB callbacks |
| `--max-blocks` | 12 | abort after N WAF/IP-block responses (`0` = never) |
| `--block-cooldown` | 0 | seconds to pause after each block response |
| `--ban-wait` | 0 | on apparent ban, wait N seconds and rotate proxy (up to 3 times) before aborting |
| `--proxy-file` | - | file of proxy URLs; rotate to the next one on each block |

Create `proxies.txt`:
```
http://user:pass@proxy1.example:8080
http://user:pass@proxy2.example:8080
socks5://proxy3.example:1080
```
Then:
```bash
python3 xssforge.py -u 'URL?q=x' --authorized --proxy-file proxies.txt \
  --max-blocks 10 --block-cooldown 2
```
On each block response the tool switches all scanner sessions to the next
proxy (wrapping around). With one proxy it just keeps using it. Note: browser
proof (`--browser`) is created at startup and does not hot-swap proxies — use
proxies that work for both the HTTP scanner and Chromium if you need browser
proof during rotation.

### IP / WAF block handling
When a response looks like a block (HTTP 401/403/406/429/501/503 or a block
phrase such as "Access denied", "captcha", "security policy"), the tool records
it, warns once, and — after `--max-blocks` responses — stops the whole scan and
labels the report as incomplete. This prevents burning your IP on a ban loop.

```bash
# gentle scan, stop early if the WAF starts blocking
python3 xssforge.py -u 'URL?q=x' --authorized --threads 2 --delay 0.5 \
  --max-blocks 5 --block-cooldown 3
```

If the **URL/IP is banned outright**, the tool now labels it explicitly:
```
! URL/IP ban detected: N WAF/block responses — Scan stopped — results are incomplete.
  recovery: wait for the ban to expire, change IP or supply --proxy-file proxies.txt...
```
With `--proxy-file` (2+ proxies) and `--ban-wait SEC`, it instead waits and
rotates to the next proxy up to 3 times before aborting:
```bash
python3 xssforge.py -u 'URL?q=x' --authorized --proxy-file proxies.txt \
  --ban-wait 30 --max-blocks 10 --delay 0.5
```
Otherwise: wait for the ban to expire, change IP, lower `--threads`, raise
`--delay`, and re-run with a real UA/cookies (`-c`). The JSON report records
`meta.http_blocks`, `meta.http_block_events`, `meta.banned` and
`meta.ban_recoveries`; the HTML report shows the block count and "incomplete" note.

```bash
# through Burp
python3 xssforge.py -u 'https://target/?q=x' --proxy http://127.0.0.1:8080 \
  --insecure --authorized
```

---

## 12. Output and reporting

- `--output-dir DIR` report/evidence folder (default `xssforge-out`)
- `--report json,jsonl,toml,html,md,sarif` which formats to write (default json,html,md)
- `--only-poc` keep only tier V/A evidence (verified/actionable); drops pure reflections
- `--min-confidence high` drop low-confidence reflection candidates
- `--waf-min-confidence N` suppress WAF attribution below N% confidence
- `--ai-fallback` opt-in LLM payload generator (needs `XSSFORGE_AI_KEY`; `--ai-model`, `--ai-count`)
- `--json` print a JSON summary to stdout (also disables color)
- `--evidence-max N` cap saved response files (default 150)
- `--show-evidence` print evidence file paths and curl commands
- `--quiet` less console output
- `--no-color` / `--no-banner` cleaner logs
- `--all` one-shot: crawl + browser + DOM + fragment + encoders

Evidence files contain the HTTP response; screenshots are saved for browser
verifications. Every candidate carries a tier and detection method:

| Tier | Meaning |
|---|---|
| **V** | verified — browser dialog/DOM execution observed, or OOB callback |
| **A** | actionable — executable reflection, OOB, or known-vulnerable library |
| **R** | reflection only — echo observed, execution not proven |
| **I** | informational — static/low-confidence candidate |

`detection_method` is one of `browser`, `dom-verification`, `oob`, `library`,
`csti`, `encoded-reflection`, `ast` or `reflection`, and
`confidence_reason` is a human-readable justification. The same fields appear
in JSON/JSONL/TOML/SARIF and the console (`tier=V method=browser`).

### Screenshots in the HTML report
`--embed-shots` (default on) embeds **confirmed** screenshots directly in the
HTML report as base64 thumbnails, so the file is self-contained. The report has
an "Execution screenshots" section plus thumbnails in the Proof column;
Markdown gets `![screenshot](...)` links. Use `--no-embed-shots` to keep the
HTML small and only link the saved PNGs in `xssforge-out/<host>/screens/`.

- **Reflected / first-hit**: screenshot captured by the browser oracle when
  `alert`/`prompt`/DOM sink fires.
- **DOM**: `--dom` static source→sink findings are code-level only (no
  screenshot). With `--dom-fuzz --fragment --browser`, confirmed fragment/DOM
  payloads do get screenshots.
- **Stored**: `--stored-url`/`--sxss-url` browser-verifies each seeded payload;
  confirmations get a screenshot and report the actual seed payload that
  executed. Attachment/download trigger responses are skipped.
- **DOM static**: `--dom` now runs both the regex pass and the structural
  tokenizer pass (`xf_ast`), covering class fields, getters, param defaults,
  destructuring, module exports, jQuery `attr/prop/wrap` and
  `document.currentScript.src`.

---

## 13. One-shot and recipes

### Methodology hunt plan (`--hunt`)
`--hunt` prints a prioritized plan from passive signals (sanitizer version,
postMessage, OAuth params, upload, markdown editors, RSC/LLM surfaces, CSP and
dangerous sinks). It is read-only, included automatically in `--full`, and saved
in `meta.hunt`:

```bash
python3 xssforge.py -u '<URL>' --hunt --authorized --cookie-file cookies.txt
```

### Universal preset — no per-site flag changes
`--full` combines `--all` (crawl, browser, DOM, fragment, encoders, HPP,
structural, header/cookie sweep, param mining) with automatic filter
fingerprinting (`--auto`), browser execution proof, first-hit escalation,
retries, a longer timeout/browser wait, and all report formats.

```bash
# Public site
python3 xssforge.py -u 'https://target/?q=x' --full --authorized

# Authenticated site (DVWA, labs, apps)
python3 xssforge.py -u 'http://192.168.0.117/DVWA/vulnerabilities/xss_r/?name=x' \
  --full --cookie-file cookies.txt --authorized
```
You still pass the target URL and, when needed, session cookies and a stored
render URL (`--sxss-url`) — those are target facts, not code changes. The tool
adapts payloads/encoders/canary style, detects WAF challenges and session loss,
and refuses to call interstitial echoes findings.

### First-hit exploit workflow (find one reflection, escalate, show payload)

```bash
python3 xssforge.py -u 'https://target/?q=x' --authorized --browser --first-hit
```

`--first-hit` sweeps the corpus **until the first reflection is found**, then
stops the sweep and uses that payload as a seed for every encoder (URL, HTML
entities, base64, UTF-7/16, JS escapes, ...), every bypass technique (case,
comments, entity-call, angle-entity, concat, ...), and the mutation engine.
Each variant is sent to the server and checked in headless Chromium; the first
variant that proves execution becomes the reported exploit.

- `--first-hit-max N` — variants to try in the escalation pass (default 30).
- `--exploit-out FILE` — where to save the winning payload (default
  `xssforge-out/exploit-<timestamp>.txt`).
- If the WAF blocks every executable payload before one can reflect, the tool
  falls back to escalating the strongest corpus vector anyway.
- The final `[EXPLOIT PAYLOAD]` block prints status, vector, the exact payload
  (with `__M__` canary), a curl reproducer and the screenshot path.
- Works together with `--stored-url` and `--dom`/`--dom-fuzz`: stored seeds and
  DOM fragment payloads are included in exploit selection, and stored
  confirmations report the **actual seed payload** that executed.

### Everything (start here on a new target)

```bash
python3 xssforge.py -u 'https://target/' --all --threads 12 --authorized
```

`--all` enables `--crawl`, `--browser`, `--dom`, `--dom-fuzz`, `--fragment`,
and `--encode all`. It does **not** enable path/stored/blind — add those
explicitly.

### Reflected XSS with proof

```bash
python3 xssforge.py -u 'https://target/search?q=hi' --browser --authorized
```

### Authenticated crawl

```bash
python3 xssforge.py -u 'https://target/' --crawl --crawl-max-pages 100 \
  --login-url 'https://target/login' --login-data 'user=me&pass=secret' \
  --threads 12 --browser --authorized
```

### JSON API

```bash
python3 xssforge.py -u 'https://api.target/v1/search' -d '{"q":"x"}' -X POST \
  --dom-fuzz --browser --authorized
```

### From Burp

```bash
python3 xssforge.py --raw req.txt --scheme https --inject-header X-Forwarded-For \
  --browser --authorized
```

### Stored

```bash
python3 xssforge.py -u 'https://target/comment' -d 'text=x' -X POST \
  --stored-url 'https://target/posts/1' --browser --authorized
```

### Blind

```bash
python3 xssforge.py -u 'https://target/feedback' -d 'msg=x' --interactsh \
  --authorized --browser
```

### WAF-heavy target

```bash
python3 xssforge.py -u 'https://target/?q=x' --encode all \
  --mutate-base 8 --mutate-max 40 --bypass-variants 3 \
  --browser --authorized
```

### Only your payload list

```bash
python3 xssforge.py -u 'https://target/?q=x' --payloads mine.txt \
  --payload-limit 0 --no-mutate --no-bypass --authorized
```

---

## 14. Troubleshooting

| Symptom | Fix |
|---|---|
| "Refusing to run" | add `--authorized` after confirming scope |
| Custom file ignored | it should not be now; custom payloads are first and unlimited. Check file exists and has one payload per line |
| Reflected but not CONFIRMED | add `--browser` (and Chromium + chromedriver on PATH) |
| Nothing reflected at all | value may be used client-side: `--dom-fuzz --browser`, `--fragment`, or `--crawl` |
| WAF blocks everything | report shows blocked count; use `--encode all`, more `--bypass-variants`, or `--raw` with real headers |
| `--auto` says "login/register page returned" | session is missing/invalid: supply `-c`/`--cookie-file` or a Burp session; payload phase is skipped on purpose |
| `--auto` says "WAF/bot challenge page" | the echo is an interstitial, not app output; slow down/rotate via `--proxy-file`, or test from an authenticated browser |
| Very slow | lower `--payload-limit`, avoid `--payload-limit 0`, keep `--delay` small, increase `--threads` |
| Browser unavailable | install chromium + chromedriver, or match versions |
| Stored not detected | supply the correct `--stored-url` and auth; verify manually that the input renders |
| Blind never fires | callback not reachable; use a public `--oob-host`, or `--interactsh` |
| Many false "LIKELY" | rerun with `--browser`; encoded/literal echoes are no longer marked LIKELY |

---

## 15. XSS coverage matrix

Run `python3 xssforge.py --coverage` for the live list. Summary:

- Automated: reflected, stored workflow, DOM static + fuzz, blind, mXSS,
  polyglot, WAF/filter bypass, encodings (base64/data-URI/UTF-7/UTF-16/URL/
  entity/JS escapes), client-side template injection, Markdown, header/cookie,
  path/fragment, JSON/multipart, OAuth redirect_uri.
- Payload+manual: CSP bypass, JSONP gadgets, postMessage, prototype pollution,
  SVG/file-upload, self-XSS/CSRF-XSS, legacy Flash/PDF.

Manual validation is always required before reporting.
