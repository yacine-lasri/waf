# 🛡️ WAF — Web Application Firewall in C

A production-style Web Application Firewall built from scratch in C, step by step. This project demonstrates network programming, HTTP parsing, and defense-in-depth web application security — evolving from a basic TCP socket to a resilient firewall capable of defeating real-world attack evasions.

Built following [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/).

---

## 🏗️ Architecture

```
                    ┌────────────────────────────────────────┐
                    │            WAF (port 8080)             │
                    │                                        │
  Client ─────────► │  1. Buffered TCP Multi-Read Loop       │
  (browser/curl)    │     - Read timeout (3s slow-client DoS)│
                    │     - Full header & body accumulation  │
                    │                                        │
                    │  2. Protocol & Smuggling Validation    │
                    │     - Reject conflicting Content-Length│
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

The WAF operates as a reverse proxy sitting inline between client traffic and the origin web application. It intercepts every TCP segment, normalizes and decodes input streams, evaluates threats across all protocol surfaces, and drops malicious payloads before they reach the server.

---

## 🗂 Project Roadmap & Learning Milestones

| Step | File | Core Concept & What You Learn |
|:---:|---|---|
| **01** | `step01_server.c` | **POSIX Sockets**: `socket()`, `bind()`, `listen()`, `accept()`, `recv()`, `SO_REUSEADDR`, endianness (`htons`). |
| **02** | `step02_backend.c`<br>`step02_proxy.c` | **Reverse Proxying**: Infinite accept loops, outbound `connect()`, dual-socket forwarding and relaying. |
| **03** | `step03_http_parser.c` | **HTTP/1.1 Dissection**: Boundary parsing via `\r\n` and `\r\n\r\n`, extracting method, path, headers, and body. |
| **04** | `step04_waf_rules.c` | **Signature Rule Engine**: Pattern matching for SQLi, XSS, Path Traversal, and Command Injection with custom 403 error pages. |
| **05** | `step05_waf_complete.c` | **Complete Hardened WAF**: Multi-read stream buffering, URL & double-decoding canonicalization, SQL comment de-obfuscation, header surface auditing, request smuggling defense, URI size validation, rate limiting, and persistent audit logging. |

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

### 5. HTTP Protocol Integrity & Smuggling Defense
- **Conflicting Headers**: Drops requests with duplicate, conflicting `Content-Length` headers (`400 Bad Request`) to prevent desynchronization / request smuggling.
- **URI Length Enforcement**: Enforces a strict 4096-byte URI limit, responding with `414 URI Too Long` to prevent buffer exhaustion and evasion by padding.

### 6. Per-IP Rate Limiting
- Evaluates request rates per client IP over a sliding 60-second window.
- Drops excess traffic with `429 Too Many Requests` and sends a `Retry-After` header.

---

## 🛡️ Evasion Defenses & Stream Hardening

During comprehensive testing, naive signature WAFs fail against obfuscation. SentinelNet includes dedicated mitigation layers:

| Attack Vector | Evasion Technique | Vulnerability in Basic WAFs | SentinelNet Mitigation |
|:---|:---|:---|:---|
| **Percent Encoding** | `union%20select` | Looked for literal `' '` (0x20); bypassed by `%20`. | In-flight **`url_decode()` pass** converts hex encodings before pattern matching. |
| **Double Encoding** | `%2527 OR 1=1` | `%2527` decoded once becomes `%27`, bypassing single-pass decoders. | **Multi-round decoding pipeline** checks raw, single-decoded, and double-decoded variants. |
| **SQL Comment Inlining** | `UN/**/ION SEL/**/ECT` | `/**/` splits keywords or acts as non-space whitespace. | **`strip_sql_comments()` engine** strips block comments to both empty string and whitespace variants. |
| **Header Injections** | `User-Agent: ' OR 1=1--` | WAF only inspected URI and Body; ignored headers. | Deep surface auditing across **`User-Agent`**, **`Referer`**, **`Cookie`**, and **`Host`**. |
| **Split TCP Headers** | `GET / HTTP` ...pause... `/1.1` | Single `recv()` returned partial segment; dropped as malformed. | **Multi-read streaming loop** buffers input until header delimiter `\r\n\r\n` arrives. |
| **Delayed POST Body** | Headers sent, body delayed 1s | Single `recv()` captured headers only; body bypassed inspection. | Content-Length aware buffering reads until **`body_bytes >= Content-Length`** before rule evaluation. |
| **Slow Client Starvation**| Client connects and sends nothing | Single-threaded server blocked indefinitely in `recv()`. | **`SO_RCVTIMEO` socket timeout (3s)** frees connection if client goes idle. |

---

## 🧪 Master Test Suite (40/40 Passing)

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
```

---

## 📝 Persistent Audit Logging

All requests, outcomes, and detection rules are written in real-time to `waf_log.txt`:

```
[2026-10-24 00:18:44] 127.0.0.1 GET / ALLOWED
[2026-10-24 00:18:44] 127.0.0.1 GET /login?user=admin'%20OR%201=1-- BLOCKED (SQL Injection: OR 1=1-- [in Query String])
[2026-10-24 00:18:45] 127.0.0.1 POST /submit BLOCKED (SQL Injection: UNION SELECT [in Body])
[2026-10-24 00:18:45] 127.0.0.1 GET / BLOCKED (SQL Injection: OR 1=1-- [in User-Agent Header])
[2026-10-24 00:18:46] 127.0.0.1 POST / BLOCKED (Conflicting Content-Length headers)
[2026-10-24 00:18:47] 127.0.0.1 GET /ping_101 RATE-LIMITED
```

---

## 🧠 Known Architectural Limitations (Engineering Deep Dive)

Understanding what a security system *cannot* do is as important as understanding what it can. For technical discussions and systems interviews:

1. **Single-Threaded Blocking Accept Loop vs. Event-Driven Concurrency (`epoll`)**:
   - *Current Implementation*: Uses standard blocking `accept()` with socket read timeouts (`SO_RCVTIMEO`).
   - *Limitation*: While the 3-second timeout prevents permanent starvation, concurrent throughput is serialized. A production WAF requires an asynchronous event loop (`epoll` / `kqueue` / `io_uring`) or a multi-threaded worker pool.
2. **Signature Matching vs. Semantic AST Analysis (e.g. Libinjection)**:
   - *Current Implementation*: Normalizes input via URL decoding and comment-stripping, then executes case-insensitive substring searches.
   - *Limitation*: Highly sophisticated SQL dialects (e.g., esoteric concatenation, mathematical boolean transforms like `' OR 2>1`) can theoretically evade regexes. Production engines (ModSecurity, Cloudflare WAF) combine regex CRS with SQL/HTML lexical tokenizers.
3. **Fixed Window vs. Token Bucket Rate Limiting**:
   - *Current Implementation*: Fixed 60-second window reset per IP.
   - *Limitation*: A client can consume their limit at second 59 and consume another full quota at second 61 (2x burst). A Token Bucket or Leaky Bucket algorithm provides smoother traffic shaping.
4. **TLS / HTTPS Termination**:
   - *Current Implementation*: Plaintext HTTP/1.1 proxy.
   - *Limitation*: Inspecting encrypted HTTPS requires integrating an SSL/TLS layer (such as OpenSSL or mbedTLS) or deploying behind an upstream TLS terminator (HAProxy, Nginx, AWS ALB).

---

## License

MIT License — see [LICENSE](LICENSE) for details.
