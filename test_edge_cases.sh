#!/bin/bash
# test_edge_cases.sh — Tests designed to probe boundary conditions and fail
#
# Tests:
# 1. Slowloris drip-feed (1 byte every 1.5s vs SO_RCVTIMEO)
# 2. Chunked Transfer-Encoding payload bypass
# 3. Unicode / IIS-style %u0027 encoding
# 4. JSON body with unicode escape (\u0027)
# 5. Single traversal in query string (?page=../admin/config.php)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}=================================================================${RESET}"
echo -e "${CYAN}${BOLD}          Testing Potential Bypasses & Edge Cases                ${RESET}"
echo -e "${CYAN}${BOLD}=================================================================${RESET}"
echo ""

# -----------------------------------------------------------------------------
# Test 1: Slowloris Drip-Feed Test
# -----------------------------------------------------------------------------
echo -e "${YELLOW}--- 1. Slowloris Drip-Feed (Per-Call Timeout vs Total Deadline) ---${RESET}"
# Start a client sending 1 byte every 1.5s (timer resets each time!)
(
    for i in {1..8}; do
        printf "X"
        sleep 1.2
    done
) | nc localhost 8080 >/dev/null 2>&1 &
SLOW_PID=$!

sleep 1
# Try to make a normal request while the slow client is trickling data
START_T=$(date +%s)
CONCURRENT_RES=$(curl -s -o /dev/null -w "%{http_code}" --max-time 4 "http://localhost:8080/" 2>/dev/null)
END_T=$(date +%s)
ELAPSED=$((END_T - START_T))

kill $SLOW_PID 2>/dev/null
wait $SLOW_PID 2>/dev/null

if [ "$CONCURRENT_RES" = "200" ]; then
    printf "  ${GREEN}[RESILIENT]${RESET} Concurrent client succeeded in %ds (Code: %s)\n" "$ELAPSED" "$CONCURRENT_RES"
else
    printf "  ${RED}[VULNERABLE]${RESET} Slowloris hung the server! Concurrent client timed out/got: '%s' after %ds\n" "$CONCURRENT_RES" "$ELAPSED"
fi
echo ""

# -----------------------------------------------------------------------------
# Test 2: Chunked Transfer-Encoding Bypass Guard
# -----------------------------------------------------------------------------
echo -e "${YELLOW}--- 2. Chunked Transfer-Encoding (TE.CL / Blind Bypass Guard) ---${RESET}"
# Send SQLi hidden inside Transfer-Encoding: chunked without Content-Length
CHUNKED_PAYLOAD=$(printf "POST /submit HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n21\r\nusername=admin' union select * --\r\n0\r\n\r\n")
CHUNKED_RES=$(echo -ne "$CHUNKED_PAYLOAD" | nc -w 3 localhost 8080 2>/dev/null | head -1)

if echo "$CHUNKED_RES" | grep -qE "400|403"; then
    printf "  ${GREEN}[REJECTED]${RESET} Chunked Transfer-Encoding rejected by WAF (Got: %s)\n" "$CHUNKED_RES"
else
    printf "  ${RED}[BYPASS]${RESET} Chunked payload passed through uninspected! (Got: %s)\n" "$CHUNKED_RES"
fi
echo ""

# -----------------------------------------------------------------------------
# Test 3: Unicode / IIS %u0075 Encoding
# -----------------------------------------------------------------------------
echo -e "${YELLOW}--- 3. Unicode / Non-Standard %uXXXX Hex Encoding ---${RESET}"
UNICODE_RES=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/?q=%u0075%u006e%u0069%u006f%u006e%20select" 2>/dev/null)

if [ "$UNICODE_RES" = "403" ]; then
    printf "  ${GREEN}[BLOCKED]${RESET} %%u0075 encoding blocked (Got: %s)\n" "$UNICODE_RES"
else
    printf "  ${RED}[BYPASS / LIMITATION]${RESET} %%u0075 passed through (Got: %s) — requires %%u decoder\n" "$UNICODE_RES"
fi
echo ""

# -----------------------------------------------------------------------------
# Test 4: JSON Body with Unicode Escape Sequence (\u0075\u006e\u0069\u006f\u006e)
# -----------------------------------------------------------------------------
echo -e "${YELLOW}--- 4. JSON Body with \\uXXXX Escape ---${RESET}"
JSON_RES=$(echo -ne '{"query":"\\u0075\\u006e\\u0069\\u006f\\u006e select"}' | curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d @- "http://localhost:8080/api" 2>/dev/null)

if [ "$JSON_RES" = "403" ]; then
    printf "  ${GREEN}[BLOCKED]${RESET} JSON \\u escape blocked (Got: %s)\n" "$JSON_RES"
else
    printf "  ${RED}[BYPASS / LIMITATION]${RESET} JSON \\u escape passed through (Got: %s) — requires JSON parser\n" "$JSON_RES"
fi
echo ""

# -----------------------------------------------------------------------------
# Test 5: Single Traversal in Query Parameter (?page=../admin/config.php)
# -----------------------------------------------------------------------------
echo -e "${YELLOW}--- 5. Single Traversal in Query Parameter ---${RESET}"
SINGLE_TRAV_RES=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/view?page=../admin/config.php" 2>/dev/null)

if [ "$SINGLE_TRAV_RES" = "403" ]; then
    printf "  ${GREEN}[BLOCKED]${RESET} ../admin/config.php was blocked (Got: %s)\n" "$SINGLE_TRAV_RES"
else
    printf "  ${RED}[BYPASS / TRADEOFF]${RESET} ../admin/config.php passed through (Got: %s) — FP tuning tradeoff\n" "$SINGLE_TRAV_RES"
fi
echo ""
