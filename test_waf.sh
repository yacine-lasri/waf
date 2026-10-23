#!/bin/bash
# =============================================================================
# WAF Security Test Suite
# =============================================================================
# This script tests the Web Application Firewall by sending crafted HTTP
# requests through curl and checking the response status codes.
#
# PREREQUISITES:
#   1. The backend server must be running (listening on its configured port)
#   2. The WAF proxy must be running on localhost:8080
#   Start both before running this script!
#
# USAGE:
#   chmod +x test_waf.sh
#   ./test_waf.sh
#
# Each test sends a request and checks whether the WAF correctly:
#   - ALLOWS clean/legitimate requests (expects HTTP 200)
#   - BLOCKS malicious requests      (expects HTTP 403)
# =============================================================================

# ---------------------------------------------------------------------------
# Color codes for pretty terminal output
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Counters — we tally passes and failures as we go
# ---------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

# ---------------------------------------------------------------------------
# run_test  —  the core helper that every test case calls
#
#   $1  description   A short human-readable label for the test
#   $2  expected      The HTTP status code we expect (200 or 403)
#   $3+ curl_args     The full curl arguments (URL, method, data, etc.)
#
# We use curl's -w "%{http_code}" to capture just the status code,
# discarding the response body with -o /dev/null and silencing the
# progress bar with -s.
# ---------------------------------------------------------------------------
run_test() {
    local description="$1"
    local expected="$2"
    shift 2

    # Execute the curl request; capture only the HTTP status code
    local actual
    actual=$(curl -s -o /dev/null -w "%{http_code}" "$@")

    TOTAL_COUNT=$((TOTAL_COUNT + 1))

    if [ "$actual" = "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  ${GREEN}[PASS]${RESET} %-40s -> %s\n" "$description" "$actual"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        printf "  ${RED}[FAIL]${RESET} %-40s -> %s  ${RED}(EXPECTED %s)${RESET}\n" \
               "$description" "$actual" "$expected"
    fi
}

# ===========================================================================
#                            BANNER
# ===========================================================================
echo ""
echo -e "${CYAN}${BOLD}=======================================================${RESET}"
echo -e "${CYAN}${BOLD}          WAF Security Test Suite${RESET}"
echo -e "${CYAN}${BOLD}=======================================================${RESET}"
echo -e "${YELLOW}  Target: http://localhost:8080${RESET}"
echo ""

# ===========================================================================
# 1. CLEAN REQUESTS  —  these should pass through the WAF untouched (200)
# ===========================================================================
echo -e "${BOLD}--- Clean Requests (expect 200) ---${RESET}"

run_test "GET /"                          200 \
    "http://localhost:8080/"

run_test "GET /api/data"                  200 \
    "http://localhost:8080/api/data"

run_test "POST /submit (form data)"       200 \
    -X POST -d "user=john&email=john@email.com" \
    "http://localhost:8080/submit"

echo ""

# ===========================================================================
# 2. SQL INJECTION  —  the WAF should block all of these (403)
# ===========================================================================
echo -e "${BOLD}--- SQL Injection (expect 403) ---${RESET}"

# Classic tautology attack:  ' OR 1=1--
run_test "SQLi: OR 1=1"                  403 \
    "http://localhost:8080/login?user=admin'%20OR%201=1--"

# UNION-based extraction attempt
run_test "SQLi: UNION SELECT"            403 \
    -X POST -d "query=1 UNION SELECT * FROM users" \
    "http://localhost:8080/search"

# Stacked query / DROP TABLE
run_test "SQLi: DROP TABLE"              403 \
    -X POST -d "id=1; DROP TABLE users" \
    "http://localhost:8080/api"

echo ""

# ===========================================================================
# 3. CROSS-SITE SCRIPTING (XSS)  —  should be blocked (403)
# ===========================================================================
echo -e "${BOLD}--- XSS Attacks (expect 403) ---${RESET}"

# Reflected XSS via query parameter
run_test "XSS: <script> tag"             403 \
    "http://localhost:8080/page?q=<script>alert('xss')</script>"

# Event-handler-based XSS in POST body
run_test "XSS: <img onerror>"            403 \
    -X POST -d "comment=<img onerror=alert(1)>" \
    "http://localhost:8080/comment"

# javascript: URI scheme in a redirect parameter
run_test "XSS: javascript: URI"          403 \
    "http://localhost:8080/redir?url=javascript:alert(1)"

echo ""

# ===========================================================================
# 4. PATH TRAVERSAL  —  attempts to escape the web root (403)
# ===========================================================================
echo -e "${BOLD}--- Path Traversal (expect 403) ---${RESET}"

# Direct ../ sequences in the URL path
run_test "Traversal: ../../../../etc/passwd" 403 \
    "http://localhost:8080/../../../../etc/passwd"

# URL-encoded ../ in a query parameter (%2f = /)
run_test "Traversal: encoded in param"       403 \
    "http://localhost:8080/files?path=..%2f..%2fetc%2fpasswd"

echo ""

# ===========================================================================
# 5. COMMAND INJECTION  —  attempts to run shell commands (403)
# ===========================================================================
echo -e "${BOLD}--- Command Injection (expect 403) ---${RESET}"

# Semicolon-separated command appended to legitimate input
run_test "CMDi: ; cat /etc/passwd"       403 \
    -X POST -d "host=localhost; cat /etc/passwd" \
    "http://localhost:8080/ping"

# Pipe operator to chain a command
run_test "CMDi: | ls -la"               403 \
    -X POST -d "cmd=test | ls -la" \
    "http://localhost:8080/run"

echo ""

# ===========================================================================
#                         SUMMARY
# ===========================================================================
echo -e "${CYAN}${BOLD}=======================================================${RESET}"
echo -e "${BOLD}  Summary${RESET}"
echo -e "${CYAN}${BOLD}=======================================================${RESET}"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All tests passed!${RESET}"
else
    echo -e "  ${RED}${BOLD}Some tests failed.${RESET}"
fi

echo -e "  ${GREEN}Passed: ${PASS_COUNT}/${TOTAL_COUNT}${RESET}"
echo -e "  ${RED}Failed: ${FAIL_COUNT}/${TOTAL_COUNT}${RESET}"
echo ""

# Exit with failure status if any test failed — useful for CI pipelines
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi

exit 0
