# 🛡️ WAF — Web Application Firewall in C

A hardened learning-stage Web Application Firewall built in C, step by step. Developed as an interactive systems programming project pair-programmed with Google Antigravity (Advanced Agentic AI Coding Assistant), following [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/).

This project explores POSIX network programming, HTTP/1.1 parsing, and defense-in-depth web application security — evolving from a raw TCP socket to a reverse-proxy firewall that handles common evasions, protocol edge cases, and stream buffering.

---

## 🏗️ Architecture

```
                    ┌────────────────────────────────────────┐
                    │            WAF (port 8080)             │
                    │                                        │
  Client ─────────► │  1. Buffered TCP Multi-Read Loop       │
  (browser/curl)    │     - Monotonic per-request deadline   │
                    │       (3s cap defends slowloris)       │
                    │     - Full header & body accumulation  │
                    │                                        │
                    │  2. Protocol & Smuggling Validation    │
                    │     - Reject conflicting CL.CL / CL.TE │
                    │     - Reject unhandled chunked bodies  │
                    │     - Enforce URI limits (< 4096B)     │
                    │                                        │
                    │  3. Multi-Round Canonicalization       │
                    │     - URL percent-decoding             │
                    │     - Double-decoding evasion guard    │
                    │     - SQL comment-stripping (/*...*/)  │
                    │                                        │
                    │  4. Full-Surface Inspection            │
                    │     - URI path & query parameters      │
                    │     - POST / PUT body data             │
                    │     - User-Agent, Referer, Cookie, Host│
                    │                                        │
                    │  5. Rate Limiting (Sliding Window)     │
                    │                                        │
                    │  6a. BLOCK ──► 400 / 403 / 414 / 429   │
                    │  6b. ALLOW ──► Relay to Backend ───────┼──► Backend (port 8888)
                    └────────────────────────────────────────┘
```

The WAF operates as a reverse proxy sitting inline between client traffic and the origin web application. It intercepts incoming TCP streams, normalizes and decodes input buffers, evaluates threat signatures across HTTP protocol surfaces, and drops malicious payloads before they can reach the server.

---

## 🗂 Project Roadmap & Learning Milestones

| Step | File | Core Concept & What You Learn |
|:---:|---|---|
| **01** | `step01_server.c` | **POSIX Sockets**: `socket()`, `bind()`, `listen()`, `accept()`, `recv()`, `SO_REUSEADDR`, endianness (`htons`). |
| **02** | `step02_backend.c`<br>`step02_proxy.c` | **Reverse Proxying**: Infinite accept loops, outbound `connect()`, dual-socket forwarding and relaying. |
| **03** | `step03_http_parser.c` | **HTTP/1.1 Dissection**: Boundary parsing via `\r\n` and `\r\n\r\n`, extracting method, path, headers, and body. |
| **04** | `step04_waf_rules.c` | **Signature Rule Engine**: Pattern matching for SQLi, XSS, Path Traversal, and Command Injection with custom 403 error pages. |
| **05** | `step05_waf_complete.c` | **Complete Hardened WAF**: Multi-read stream buffering, dynamic Slowloris deadline (`clock_gettime`), URL & double-decoding canonicalization, SQL comment de-obfuscation, header surface auditing, request smuggling & chunked TE guards, URI size validation, rate limiting, and persistent audit logging. |

---

## 🔒 Security Engine & Threat Signatures

### 1. SQL Injection (SQLi)
- **Authentication Bypasses**: `' OR 1=1`, `' OR '1'='1`, `OR 1=1--`, `1'='1`
- **Data Exfiltration**: `UNION SELECT`, `UNION ALL`
- **Destructive Queries**: `DROP TABLE`, `DROP DATABASE`, `; DELETE`, `; INSERT`, `; UPDATE`
- **Blind & Time-Based Extraction**: `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY`
- **File System / Shell Access**: `INTO OUTFILE`, `INTO DUMPFILE`, `LOAD_FILE()`

### 2. Cross-Site Scripting (XSS)
- **Tags & Protocols**: `<script>`, `</script>`, `<iframe>`, `<object>`, `<embed>`, `<svg>`, `javascript:`, `vbscript:`
- **Event Handlers**: `onerror=`, `onload=`, `onclick=`, `onmouseover=`, `onfocus=`, `onblur=`
- **DOM / Execution Hooks**: `eval()`, `alert()`, `document.cookie`, `document.write`, `window.location`

### 3. Path Traversal & LFI
- **Traversal Climbing**: `../` (strict path evaluation), `..\`, `../../`
- **System Targets**: `/etc/passwd`, `/etc/shadow`, `/proc/self`, `c:\windows`, `boot.ini`, `win.ini`
- **False-Positive Tuning**: Permits legitimate relative asset paths in parameters (e.g. `?bg=../images/logo.png`) while blocking directory traversal attempts.

### 4. Command Injection (CMDi)
- **Command Chaining & Pipes**: `; cat`, `| cat`, `; ls`, `| ls`, `; rm -rf`, `&&`, `||`
- **Subshells & Substitution**: `` `cmd` ``, `$(cmd)`
- **Reverse Shell & Downloaders**: `; nc`, `; curl`, `; wget`, `/bin/sh`, `/bin/bash`

### 5. HTTP Protocol Integrity & Focused Smuggling Defense
- **Conflicting Headers (CL.CL / CL.TE)**: Rejects requests with duplicate `Content-Length` headers or conflicting `Content-Length` + `Transfer-Encoding` (`400 Bad Request`) to prevent request smuggling desynchronization.
- **Unhandled Chunked TE Guard**: Explicitly rejects `Transfer-Encoding: chunked` (`400 Bad Request`) because without implementing a full streaming chunk de-framer, chunked payloads cannot be inspected and would otherwise bypass body inspection.
- **URI Length Enforcement**: Enforces a strict 4096-byte URI limit, responding with `414 URI Too Long` to prevent buffer exhaustion and evasion by padding.

### 6. Per-IP Rate Limiting
- Evaluates request rates per client IP over a sliding 60-second window.
- Drops excess traffic with `429 Too Many Requests` and sends a `Retry-After` header.

---

## 🛡️ Evasion Defenses & Iterative Bug Fixes

During development and testing, naive signature matching proved fragile against common obfuscation techniques. The table below documents specific bugs discovered across development iterations and the mitigations implemented in `step05_waf_complete.c`:

| Attack Vector | Evasion Technique | Observed in Step 04 / Early Code | WAF Step 05 Fix |
|:---|:---|:---|:---|
| **Percent Encoding** | `union%20select` | **Found in Step 04**: Looked for literal `' '` (0x20); bypassed completely by `%20`. | In-flight **`url_decode()` pass** converts hex encodings before pattern matching. |
| **Double Encoding** | `%2527 OR 1=1` | **Found in early Step 05**: A single-pass decode turned `%2527` into `%27`, bypassing checks. | **Multi-round decoding pipeline** checks raw, single-decoded, and double-decoded variants. |
| **SQL Comment Inlining** | `UN/**/ION SEL/**/ECT` | **Found in Step 04**: Block comments `/**/` broke keyword matching and acted as whitespace. | **`strip_sql_comments()` engine** strips block comments to both empty string and whitespace variants. |
| **Header Injections** | `User-Agent: ' OR 1=1--` | **Found in Step 04**: WAF only inspected URI query and body; completely ignored headers. | Deep surface auditing across **`User-Agent`**, **`Referer`**, **`Cookie`**, and **`Host`**. |
| **Split TCP Headers** | `GET / HTTP` ...pause... `/1.1` | **Found in Step 03/04**: Single `recv()` captured only the first segment; dropped as malformed. | **Multi-read streaming loop** buffers input until header delimiter `\r\n\r\n` arrives. |
| **Delayed POST Body** | Headers sent, body delayed 1s | **Found in Step 03/04**: Single `recv()` captured headers only; body bypassed inspection. | Content-Length aware buffering reads until **`body_bytes >= Content-Length`** before rule evaluation. |
| **Slowloris Drip-Feed** | 1 byte sent every 1.5s | **Found in early Step 05**: `SO_RCVTIMEO` reset per `recv()`, allowing slow clients to hold server indefinitely. | **Absolute per-request deadline** via `clock_gettime(CLOCK_MONOTONIC)` with dynamic `SO_RCVTIMEO` budget recalculation (3.0s total cap). |
| **Chunked TE Smuggling** | `Transfer-Encoding: chunked` | **Found in early Step 05**: Requests lacking `Content-Length` bypassed body checks. | **Smuggling & bypass guard**: Rejects conflicting TE/CL headers and unsupported chunked streams (`400 Bad Request`). |

---

## 🧪 Master Regression Test Suite (40/40 Passing)

The project includes an automated test suite (`test_waf.sh`) covering 40 deterministic security and robustness scenarios:

```bash
# With backend and WAF running:
bash test_waf.sh
```

```
=================================================================
           WAF Master Security & Robustness Suite                
=================================================================
  Target: http://localhost:8080

--- 1. Clean Requests (expect 200) ---
  [PASS] GET /                                                -> 200
  [PASS] GET /api/data?q=books                                -> 200
  [PASS] POST /submit (clean form data)                       -> 200

--- 2. Basic Attacks (expect 403) ---
  [PASS] SQLi: ' OR 1=1--                                     -> 403
  [PASS] SQLi: UNION SELECT in URL                            -> 403
  [PASS] XSS: <script> tag in URL                             -> 403
  [PASS] Path Traversal: ../../../../etc/passwd               -> 403
  [PASS] Command Injection: ; cat /etc/passwd                 -> 403

--- 3. Evasion Attempts (expect 403) ---
  [PASS] Mixed Case: UniOn SeLeCt                             -> 403
  [PASS] Mixed Case: uNiOn AlL sElEcT                         -> 403
  [PASS] Mixed Case: dRoP TaBlE                               -> 403
  [PASS] URL-Encoded: union%20select                          -> 403
  [PASS] URL-Encoded: %3Cscript%3E                            -> 403
  [PASS] URL-Encoded: %2e%2e%2f traversal                     -> 403
  [PASS] Double-Encoded: %2527 OR 1=1                         -> 403
  [PASS] Double-Encoded: %252e%252e%252f                      -> 403
  [PASS] SQL Comment: UN/**/ION SEL/**/ECT                    -> 403
  [PASS] SQL Comment: UNION/*comment*/SELECT                  -> 403
  [PASS] Payload in POST Body: union select                   -> 403
  [PASS] Payload in POST Body: <script>                       -> 403
  [PASS] Payload in POST Body: ;cat /etc/passwd               -> 403
  [PASS] Header Injection: User-Agent SQLi                    -> 403
  [PASS] Header Injection: Referer XSS                        -> 403
  [PASS] Header Injection: Cookie SQLi                        -> 403

--- 4. False Positives (expect 200) ---
  [PASS] Legitimate: European Union history                   -> 200
  [PASS] Legitimate: select a color                           -> 200
  [PASS] Legitimate: O'Brien name field                       -> 200
  [PASS] Legitimate: double-dash in comment                   -> 200
  [PASS] Legitimate: drop the beat                            -> 200
  [PASS] Legitimate: movie script word                        -> 200
  [PASS] Legitimate: alert team message                       -> 200
  [PASS] Legitimate: ../images/logo.png                       -> 200

--- 5. Split & Slow Requests (expect 200) ---
  [PASS] Split Request: Header split with 0.5s pause          -> 200
  [PASS] Slow POST: Headers now, body after 0.5s pause        -> 200

--- 6. Edge Cases & Protocol Integrity ---
  [PASS] Conflicting Content-Length (Smuggling guard)         -> 400
  [PASS] Oversized URI (> 4096 bytes) -> 414                  -> 414
  [PASS] Resilience: Slow client idle timeout                 -> 200

--- 7. Robustness & Oversized Payloads ---
  [PASS] Robustness: 100 KB POST body cleanly relayed         -> 200
  [PASS] Robustness: Random garbage input resilience          -> Process survived

--- 8. Rate Limiting Burst Test (expect 429) ---
  [PASS] Rate Limiter: Burst of >30 requests throttled        -> 429 triggered

=================================================================
                       Test Suite Summary                        
=================================================================
  Passed: 40 / 40
  Failed: 0 / 40

  WAF Process Health  : ALIVE
  Audit Log Recorded  : OK (104 entries logged)

  ALL TESTS PASSED!
```

---

## 🔬 Beyond Regression: Edge Cases & Tradeoff Probes (`test_edge_cases.sh`)

A test suite where all 40 tests pass is a regression suite, not proof of total security. Real security systems are defined by their edge cases and architectural tradeoffs. 

The standalone script `test_edge_cases.sh` specifically probes boundary conditions:

```bash
bash test_edge_cases.sh
```

```
=================================================================
          Testing Potential Bypasses & Edge Cases                
=================================================================

--- 1. Slowloris Drip-Feed (Per-Call Timeout vs Total Deadline) ---
  [RESILIENT] Concurrent client succeeded in 2s (Code: 200)

--- 2. Chunked Transfer-Encoding (TE.CL / Blind Bypass Guard) ---
  [REJECTED] Chunked Transfer-Encoding rejected by WAF (Got: HTTP/1.1 400 Bad Request)

--- 3. Unicode / Non-Standard %uXXXX Hex Encoding ---
  [BYPASS / LIMITATION] %u0075 passed through (Got: 200) — requires %u decoder

--- 4. JSON Body with \uXXXX Escape ---
  [BYPASS / LIMITATION] JSON \u escape passed through (Got: 200) — requires JSON parser

--- 5. Single Traversal in Query Parameter ---
  [BYPASS / TRADEOFF] ../admin/config.php passed through (Got: 200) — FP tuning tradeoff
```

---

## ⚡ Quick Start

### 1. Build
```bash
make all
```

### 2. Run
```bash
# Terminal 1: Launch Backend Origin
./step02_backend

# Terminal 2: Launch WAF Firewall
./step05_waf_complete

# Terminal 3: Run Test Suite
bash test_waf.sh

# Terminal 4: Run Edge Case Probes
bash test_edge_cases.sh
```

---

## 📝 Persistent Audit Logging

All requests, outcomes, and detection rules are written in real-time to `waf_log.txt`:

```
[2026-10-24 10:55:26] 127.0.0.1 GET / ALLOWED
[2026-10-24 10:55:26] 127.0.0.1 GET /login?user=admin'%20OR%201=1-- BLOCKED (SQL Injection: OR 1=1 [in Query String])
[2026-10-24 10:55:27] 127.0.0.1 POST /ping BLOCKED (Path Traversal: /etc/passwd [in Body])
[2026-10-24 10:55:27] 127.0.0.1 GET /?q=UniOn%20SeLeCt%20*%20FROM%20users BLOCKED (SQL Injection: UNION SELECT [in Query String])
[2026-10-24 10:55:28] 127.0.0.1 POST / BLOCKED (Conflicting headers (Request Smuggling guard))
[2026-10-24 10:55:31] 127.0.0.1 GET /ping_101 RATE-LIMITED
```

---

## 🧠 Known Architectural Limitations (Engineering Deep Dive)

Understanding what a security system *cannot* do is as important as understanding what it can. For technical discussions and systems interviews:

### 1. Slow-Client Defense: `SO_RCVTIMEO` vs Monotonic Total Deadline
- **The Pitfall**: `SO_RCVTIMEO` specifies an inactivity timeout *per individual `recv()` system call*, not a total deadline for the entire request. A Slowloris client trickling 1 byte every 1.5 seconds continuously resets the timer, starving a single-threaded server indefinitely.
- **The Fix**: In `step05_waf_complete.c`, we track request start time via `clock_gettime(CLOCK_MONOTONIC)` with `#define TOTAL_REQUEST_DEADLINE 3.0`. On every iteration of the `recv()` loop, `SO_RCVTIMEO` is dynamically recalculated to `TOTAL_REQUEST_DEADLINE - elapsed`. If the budget is exhausted, the connection is terminated.
- **Remaining Limitation**: While this prevents indefinite starvation, concurrent connections are still serialized during that 3-second window. A production WAF requires an asynchronous event loop (`epoll` / `io_uring`) or a multi-threaded worker pool.

### 2. Chunked Transfer-Encoding & Request Smuggling Boundaries
- **Narrow Guard**: The WAF detects conflicting `Content-Length` headers and conflicting `Transfer-Encoding` + `Content-Length` pairs (`400 Bad Request`). It also explicitly rejects unhandled `Transfer-Encoding: chunked` requests (`400 Bad Request`).
- **Limitation**: The WAF does not implement a full streaming RFC 7230 chunked de-framer. Rather than forwarding uninspected chunked data (which would allow an attacker to bypass inspection or desynchronize downstream reverse proxies), the WAF rejects chunked encoding entirely. A production WAF must decode chunked streams in real-time, inspect the assembled buffer, and re-chunk or serialize with `Content-Length`.

### 3. Path Traversal False-Positive Tuning Tradeoff
- **The Tradeoff**: In `step04_waf_rules.c`, blocking any occurrence of `../` broke legitimate relative asset URLs (e.g., `?bg=../images/logo.png`). To reduce false positives, `step05_waf_complete.c` permits a single `../` in query parameters unless it targets known system files (`/etc/passwd`, `/etc/shadow`, `/proc/self`, `c:\windows`, `win.ini`).
- **The Resulting Bypass**: As demonstrated in `test_edge_cases.sh` Test 5, an attacker requesting `?page=../admin/config.php` will pass through unblocked. Without application-level route knowledge or backend chroot sandboxing, heuristic path traversal filtering faces an unavoidable tension between false positives and exploit coverage.

### 4. Encoding Boundaries: Non-Standard `%uXXXX` & JSON `\uXXXX`
- **Limitation**: The canonicalization pipeline handles standard URL percent-encoding (`%XX` with two hex digits) and SQL comment stripping. It does not parse non-standard Microsoft IIS-style `%uXXXX` encodings (`%u0075%u006e...` for `union`) or JSON string escape sequences (`\u0075\u006e\u0069\u006f\u006e`).
- **Impact**: As demonstrated in `test_edge_cases.sh` Tests 3 & 4, if a backend framework (such as IIS/ASP.NET or a JSON REST API parser) decodes these sequences prior to SQL query execution, the payload bypasses the WAF's string-matching engine. Production WAFs require content-type aware tokenizers (e.g., a native JSON parser).

### 5. Signature Matching vs Semantic AST Analysis (e.g. Libinjection)
- **Limitation**: The engine relies on case-insensitive substring search after normalization. Sophisticated SQL dialect constructs (e.g., esoteric concatenation, mathematical boolean transforms like `' OR 2>1`) can theoretically evade static signatures. Production engines (ModSecurity, Cloudflare WAF) combine regex rules with SQL/HTML lexical tokenizers.

### 6. Fixed Window vs Token Bucket Rate Limiting
- **Limitation**: The rate limiter tracks request counts in fixed 60-second windows per IP. A client could exhaust their quota at second 59 and immediately consume a second full quota at second 61 (a 2x burst). A Token Bucket or Leaky Bucket algorithm provides smoother traffic shaping.

### 7. Plaintext HTTP vs TLS/HTTPS Termination
- **Limitation**: The WAF functions exclusively as a plaintext HTTP/1.1 proxy. Inspecting encrypted HTTPS traffic requires either embedding an SSL library (OpenSSL / mbedTLS) or deploying the WAF behind an upstream TLS terminator (HAProxy, Nginx, or AWS ALB).

---

## License

MIT License — see [LICENSE](LICENSE) for details.
