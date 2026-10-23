# 🛡️ WAF — Web Application Firewall in C

A Web Application Firewall built from scratch in C, step by step. This project is a learning journey through network programming, HTTP, and web security — from a basic TCP socket to a fully functional firewall that detects and blocks real attacks.

Built following [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/).

## Architecture

```
                    ┌─────────────────────────────┐
                    │         WAF (port 8080)      │
  Client ──────▶   │  1. Receive HTTP request      │
  (browser/curl)   │  2. Parse method, path, body  │
                    │  3. Run security rules        │
                    │     - SQL Injection?          │
                    │     - XSS?                   │
                    │     - Path Traversal?         │
                    │     - Command Injection?      │
                    │     - Rate limit exceeded?    │
                    │  4a. BLOCK → 403 Forbidden   │
                    │  4b. ALLOW → forward to ─────┼──▶ Backend (port 8888)
                    └─────────────────────────────┘
```

The WAF sits between the client and the real web server. It's both a **server** (to the client) and a **client** (to the backend). Every request passes through it for inspection.

## 🗂 Project Steps

Each step builds on the previous one. Read them in order to follow the learning path.

| Step | File | What You Learn |
|------|------|----------------|
| 01 | `step01_server.c` | TCP basics: `socket()`, `bind()`, `listen()`, `accept()`, `recv()` |
| 02 | `step02_backend.c` | Server loop, HTTP responses |
| 02 | `step02_proxy.c` | TCP proxy: `connect()`, `send()`, forwarding traffic |
| 03 | `step03_http_parser.c` | HTTP parsing: splitting requests by `\r\n` into method, path, headers, body |
| 04 | `step04_waf_rules.c` | Security rules: SQLi, XSS, path traversal, command injection detection |
| 05 | `step05_waf_complete.c` | **Complete WAF**: all rules + rate limiting + logging + stats |

## 🔒 Security Rules

### SQL Injection Detection
Detects attempts to manipulate database queries:
- `' OR 1=1 --` (authentication bypass)
- `UNION SELECT` (data exfiltration)
- `DROP TABLE` (destructive queries)
- `; DELETE`, `; INSERT`, `; UPDATE` (query stacking)

### Cross-Site Scripting (XSS) Detection
Detects attempts to inject malicious scripts:
- `<script>` tags
- `javascript:` protocol URLs
- Event handlers: `onerror=`, `onload=`, `onclick=`
- `eval()`, `document.cookie`

### Path Traversal Detection
Detects attempts to access files outside the web root:
- `../` and `..\` sequences
- Direct paths like `/etc/passwd`
- URL-encoded variants (`%2e%2e%2f`)

### Command Injection Detection
Detects attempts to execute system commands:
- `; cat /etc/passwd` (semicolon injection)
- `| ls -la` (pipe injection)
- `` `whoami` `` (backtick execution)
- `$(id)` (subshell execution)

### Rate Limiting
- Tracks requests per IP address
- Configurable window (default: 60 seconds)
- Configurable limit (default: 30 requests per window)
- Returns `429 Too Many Requests` when exceeded

## 🚀 Quick Start

### Prerequisites
- GCC (Linux/WSL)
- `curl` for testing
- `make`

### Build Everything
```bash
make all
```

### Run the WAF
```bash
# Terminal 1: Start the backend server
./step02_backend

# Terminal 2: Start the WAF
./step05_waf_complete

# Terminal 3: Test it
curl http://localhost:8080/                              # → 200 OK
curl "http://localhost:8080/?q=' OR 1=1--"               # → 403 Blocked (SQLi)
curl "http://localhost:8080/?q=<script>alert(1)</script>" # → 403 Blocked (XSS)
curl "http://localhost:8080/../../../../etc/passwd"       # → 403 Blocked (Path Traversal)
```

### Run the Test Suite
```bash
# With backend + WAF running:
bash test_waf.sh
```

## 📝 Logging

The complete WAF (`step05`) logs all requests to `waf_log.txt`:
```
[2024-01-15 14:30:22] 127.0.0.1 GET /api/data ALLOWED
[2024-01-15 14:30:23] 127.0.0.1 POST /login BLOCKED (SQL Injection: UNION SELECT)
[2024-01-15 14:30:24] 10.0.0.5 GET / RATE-LIMITED
```

## 🧠 Concepts Covered

- **POSIX socket programming** — `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `send()`, `recv()`
- **TCP/IP networking** — how data travels between client and server
- **HTTP protocol** — request structure, methods, headers, status codes
- **Proxy architecture** — man-in-the-middle for inspection
- **String parsing in C** — `strstr()`, `sscanf()`, `strncpy()`, buffer management
- **Security pattern matching** — detecting attack signatures in user input
- **Rate limiting** — tracking and throttling per-IP request rates
- **File I/O** — logging to files with timestamps

## ⚠️ Disclaimer

This is a **learning project**. It demonstrates WAF concepts but is NOT production-ready. A real WAF would need:
- Multi-threading or async I/O (`poll()`/`epoll()`)
- Proper regex-based rule matching
- HTTPS/TLS termination
- Configuration files
- More comprehensive rule sets (OWASP ModSecurity CRS)
- Connection pooling
- Proper memory management and fuzzing

## License

MIT
