#!/bin/bash
# =============================================================================
# WAF Master Security & Robustness Test Suite
# =============================================================================
# Tests the Web Application Firewall across all categories:
#   1. Clean requests (200)
#   2. Basic attacks (403)
#   3. Evasion techniques (403)
#   4. False positive avoidance (200)
#   5. Split & slow TCP stream requests (200)
#   6. Rate limiting enforcement (429)
#   7. Robustness & oversized payloads (200 / handled)
#   8. Edge cases & HTTP smuggling vectors (400 / 414 / timeout resilience)
# =============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

run_test() {
    local description="$1"
    local expected="$2"
    shift 2

    local actual
    actual=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$@" 2>/dev/null)

    TOTAL_COUNT=$((TOTAL_COUNT + 1))

    if [ "$actual" = "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  ${GREEN}[PASS]${RESET} %-52s -> %s\n" "$description" "$actual"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        printf "  ${RED}[FAIL]${RESET} %-52s -> %s  ${RED}(EXPECTED %s)${RESET}\n" \
               "$description" "$actual" "$expected"
    fi
}

echo ""
echo -e "${CYAN}${BOLD}=================================================================${RESET}"
echo -e "${CYAN}${BOLD}           WAF Master Security & Robustness Suite                ${RESET}"
echo -e "${CYAN}${BOLD}=================================================================${RESET}"
echo -e "${YELLOW}  Target: http://localhost:8080${RESET}"
echo ""

# Reset / ensure audit log exists
> waf_log.txt 2>/dev/null

# -----------------------------------------------------------------------------
# 1. CLEAN REQUESTS (Expect 200)
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 1. Clean Requests (expect 200) ---${RESET}"
run_test "GET /"                          200 "http://localhost:8080/"
run_test "GET /api/data?q=books"          200 "http://localhost:8080/api/data?q=books"
run_test "POST /submit (clean form data)" 200 -X POST -d "user=john&email=john@example.com" "http://localhost:8080/submit"
echo ""

# -----------------------------------------------------------------------------
# 2. BASIC ATTACKS (Expect 403)
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 2. Basic Attacks (expect 403) ---${RESET}"
run_test "SQLi: ' OR 1=1--"                     403 "http://localhost:8080/login?user=admin'%20OR%201=1--"
run_test "SQLi: UNION SELECT in URL"            403 "http://localhost:8080/search?q=1%20UNION%20SELECT%20*%20FROM%20users"
run_test "XSS: <script> tag in URL"             403 "http://localhost:8080/page?q=<script>alert('xss')</script>"
run_test "Path Traversal: ../../../../etc/passwd" 403 "http://localhost:8080/../../../../etc/passwd"
run_test "Command Injection: ; cat /etc/passwd" 403 -X POST -d "host=localhost; cat /etc/passwd" "http://localhost:8080/ping"
echo ""

# -----------------------------------------------------------------------------
# 3. EVASION ATTEMPTS (Expect 403)
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 3. Evasion Attempts (expect 403) ---${RESET}"
run_test "Mixed Case: UniOn SeLeCt"             403 "http://localhost:8080/?q=UniOn%20SeLeCt%20*%20FROM%20users"
run_test "Mixed Case: uNiOn AlL sElEcT"         403 "http://localhost:8080/?q=uNiOn%20AlL%20sElEcT"
run_test "Mixed Case: dRoP TaBlE"               403 "http://localhost:8080/?q=dRoP%20TaBlE%20users"
run_test "URL-Encoded: union%20select"          403 "http://localhost:8080/?q=union%20select%20*%20from%20users"
run_test "URL-Encoded: %3Cscript%3E"            403 "http://localhost:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E"
run_test "URL-Encoded: %2e%2e%2f traversal"     403 "http://localhost:8080/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
run_test "Double-Encoded: %2527 OR 1=1"         403 "http://localhost:8080/?q=%2527%20OR%201%3D1"
run_test "Double-Encoded: %252e%252e%252f"      403 "http://localhost:8080/?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
run_test "SQL Comment: UN/**/ION SEL/**/ECT"    403 "http://localhost:8080/?q=UN/**/ION%20SEL/**/ECT"
run_test "SQL Comment: UNION/*comment*/SELECT"  403 "http://localhost:8080/?q=UNION/*comment*/SELECT"
run_test "Payload in POST Body: union select"   403 -X POST -d "username=admin' union select * from users--" "http://localhost:8080/login"
run_test "Payload in POST Body: <script>"       403 -X POST -d "comment=<script>alert('xss')</script>" "http://localhost:8080/comment"
run_test "Payload in POST Body: ;cat /etc/passwd" 403 -X POST -d "host=localhost;cat /etc/passwd" "http://localhost:8080/ping"
run_test "Header Injection: User-Agent SQLi"    403 -H "User-Agent: ' OR 1=1--" "http://localhost:8080/"
run_test "Header Injection: Referer XSS"        403 -H "Referer: <script>alert(1)</script>" "http://localhost:8080/"
run_test "Header Injection: Cookie SQLi"        403 -H "Cookie: session=admin' union select * from users" "http://localhost:8080/"
echo ""

# -----------------------------------------------------------------------------
# 4. FALSE POSITIVES (Expect 200)
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 4. False Positives (expect 200) ---${RESET}"
run_test "Legitimate: European Union history"   200 "http://localhost:8080/search?q=European+Union+history"
run_test "Legitimate: select a color"           200 -X POST -d "action=select+a+color" "http://localhost:8080/form"
run_test "Legitimate: O'Brien name field"       200 -X POST -d "name=O'Brien&city=Dublin" "http://localhost:8080/register"
run_test "Legitimate: double-dash in comment"   200 -X POST -d "comment=great work -- keep it up!" "http://localhost:8080/feedback"
run_test "Legitimate: drop the beat"            200 "http://localhost:8080/blog?title=drop+the+beat"
run_test "Legitimate: movie script word"        200 -X POST -d "note=the movie script was amazing" "http://localhost:8080/notes"
run_test "Legitimate: alert team message"       200 -X POST -d "msg=please alert the team" "http://localhost:8080/msg"
run_test "Legitimate: ../images/logo.png"       200 "http://localhost:8080/css?bg=../images/logo.png"
echo ""

# -----------------------------------------------------------------------------
# 5. SPLIT & SLOW TCP STREAM REQUESTS (Expect 200)
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 5. Split & Slow Requests (expect 200) ---${RESET}"
SPLIT_HEADER_RES=$(
    { echo -ne "GET /split HTTP"; sleep 0.5; echo -ne "/1.1\r\nHost: localhost\r\n\r\n"; } | nc -w 3 localhost 8080 2>/dev/null
)
if echo "$SPLIT_HEADER_RES" | grep -q "200 OK"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}[PASS]${RESET} %-52s -> 200\n" "Split Request: Header split with 0.5s pause"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}[FAIL]${RESET} %-52s -> timeout/closed  ${RED}(EXPECTED 200)${RESET}\n" "Split Request: Header split with 0.5s pause"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))

SLOW_BODY_RES=$(
    { echo -ne "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\n"; sleep 0.5; echo -ne "hello=world"; } | nc -w 3 localhost 8080 2>/dev/null
)
if echo "$SLOW_BODY_RES" | grep -q "200 OK"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}[PASS]${RESET} %-52s -> 200\n" "Slow POST: Headers now, body after 0.5s pause"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}[FAIL]${RESET} %-52s -> timeout/closed  ${RED}(EXPECTED 200)${RESET}\n" "Slow POST: Headers now, body after 0.5s pause"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))
echo ""

# -----------------------------------------------------------------------------
# 6. EDGE CASES & HTTP INTEGRITY (Expect 400 / 414 / Non-blocking)
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 6. Edge Cases & Protocol Integrity ---${RESET}"

# Duplicate/Conflicting Content-Length (HTTP Request Smuggling Vector) -> 400
SMUGGLE_RES=$(printf "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 50\r\n\r\nhello" | nc -w 3 localhost 8080 2>/dev/null)
if echo "$SMUGGLE_RES" | grep -q "400 Bad Request"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}[PASS]${RESET} %-52s -> 400\n" "Conflicting Content-Length (Smuggling guard)"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}[FAIL]${RESET} %-52s -> not 400  ${RED}(EXPECTED 400)${RESET}\n" "Conflicting Content-Length (Smuggling guard)"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))

# Oversized URL (> 4096 bytes) -> 414 URI Too Long
LONG_PATH=$(head -c 5000 /dev/zero | tr '\0' 'A')
run_test "Oversized URI (> 4096 bytes) -> 414" 414 "http://localhost:8080/$LONG_PATH"

# Slow Client Resilience Test (Connect & send nothing, verify concurrent client isn't frozen)
( nc localhost 8080 >/dev/null 2>&1 < /dev/zero & )
NC_PID=$!
sleep 0.2
CONCURRENT_RES=$(curl -s -o /dev/null -w "%{http_code}" --max-time 4 "http://localhost:8080/" 2>/dev/null)
kill $NC_PID 2>/dev/null
wait $NC_PID 2>/dev/null

if [ "$CONCURRENT_RES" = "200" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}[PASS]${RESET} %-52s -> 200\n" "Resilience: Slow client idle timeout"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}[FAIL]${RESET} %-52s -> %s  ${RED}(EXPECTED 200)${RESET}\n" "Resilience: Slow client idle timeout" "$CONCURRENT_RES"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))
echo ""

# -----------------------------------------------------------------------------
# 7. ROBUSTNESS & OVERSIZED PAYLOADS
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 7. Robustness & Oversized Payloads ---${RESET}"

# 100 KB POST body test
TMP_100K="/tmp/waf_100k_body.dat"
head -c 102400 /dev/zero | tr '\0' 'x' > "$TMP_100K"
BODY_100K_RES=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST --data-binary @"$TMP_100K" "http://localhost:8080/upload" 2>/dev/null)
rm -f "$TMP_100K"

if [ "$BODY_100K_RES" = "200" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}[PASS]${RESET} %-52s -> 200\n" "Robustness: 100 KB POST body cleanly relayed"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}[FAIL]${RESET} %-52s -> %s  ${RED}(EXPECTED 200)${RESET}\n" "Robustness: 100 KB POST body cleanly relayed" "$BODY_100K_RES"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))

# Garbage raw input test
echo -ne "\x00\xff\xfe\x01\x02\x03random_garbage_data\r\n\r\n" | nc -w 2 localhost 8080 >/dev/null 2>&1
if curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://localhost:8080/" | grep -q "200"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}[PASS]${RESET} %-52s -> Process survived\n" "Robustness: Random garbage input resilience"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}[FAIL]${RESET} %-52s -> WAF crashed\n" "Robustness: Random garbage input resilience"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))
echo ""

# -----------------------------------------------------------------------------
# 8. RATE LIMITING ENFORCEMENT (Expect 429)
# -----------------------------------------------------------------------------
echo -e "${BOLD}--- 8. Rate Limiting Burst Test (expect 429) ---${RESET}"
GOT_429=0
for i in {1..110}; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/ping_$i" 2>/dev/null)
    if [ "$CODE" = "429" ]; then
        GOT_429=1
        break
    fi
done

if [ "$GOT_429" -eq 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}[PASS]${RESET} %-52s -> 429 triggered\n" "Rate Limiter: Burst of >30 requests throttled"
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}[FAIL]${RESET} %-52s -> No 429 seen  ${RED}(EXPECTED 429)${RESET}\n" "Rate Limiter: Burst of >30 requests throttled"
fi
TOTAL_COUNT=$((TOTAL_COUNT + 1))
echo ""

# =============================================================================
# SUMMARY & POST-FLIGHT AUDIT
# =============================================================================
echo -e "${CYAN}${BOLD}=================================================================${RESET}"
echo -e "${CYAN}${BOLD}                       Test Suite Summary                        ${RESET}"
echo -e "${CYAN}${BOLD}=================================================================${RESET}"
echo -e "  Passed: ${GREEN}${PASS_COUNT}${RESET} / ${TOTAL_COUNT}"
echo -e "  Failed: ${RED}${FAIL_COUNT}${RESET} / ${TOTAL_COUNT}"
echo ""

# Check WAF liveness
if curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:8080/ 2>/dev/null | grep -q "200\|403\|429"; then
    echo -e "  WAF Process Health  : ${GREEN}ALIVE${RESET}"
else
    echo -e "  WAF Process Health  : ${RED}DEAD${RESET}"
fi

# Check audit log file
if [ -f "waf_log.txt" ] && [ -s "waf_log.txt" ]; then
    LOG_ENTRIES=$(wc -l < waf_log.txt)
    echo -e "  Audit Log Recorded  : ${GREEN}OK ($LOG_ENTRIES entries logged)${RESET}"
else
    echo -e "  Audit Log Recorded  : ${YELLOW}EMPTY or MISSING${RESET}"
fi
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}ALL TESTS PASSED!${RESET}"
    exit 0
else
    echo -e "  ${RED}${BOLD}SOME TESTS FAILED - Review failure list above.${RESET}"
    exit 1
fi
