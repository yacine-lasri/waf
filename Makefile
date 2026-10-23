# ============================================
#  WAF Project — Makefile
#
#  Build all steps:    make all
#  Build one step:     make step01
#  Clean binaries:     make clean
#  Run tests:          make test
# ============================================

CC      = gcc
CFLAGS  = -Wall -Wextra -g

# All targets
TARGETS = step01_server step02_backend step02_proxy step03_http_parser \
          step04_waf_rules step05_waf_complete

.PHONY: all clean test help

all: $(TARGETS)
	@echo ""
	@echo "=== All steps built successfully ==="
	@echo ""

# --- Step 01: Basic TCP server ---
step01: step01_server

step01_server: step01_server.c
	$(CC) $(CFLAGS) -o $@ $<

# --- Step 02: Backend + Proxy ---
step02: step02_backend step02_proxy

step02_backend: step02_backend.c
	$(CC) $(CFLAGS) -o $@ $<

step02_proxy: step02_proxy.c
	$(CC) $(CFLAGS) -o $@ $<

# --- Step 03: HTTP Parser Proxy ---
step03: step03_http_parser

step03_http_parser: step03_http_parser.c
	$(CC) $(CFLAGS) -o $@ $<

# --- Step 04: WAF with Security Rules ---
step04: step04_waf_rules

step04_waf_rules: step04_waf_rules.c
	$(CC) $(CFLAGS) -o $@ $<

# --- Step 05: Complete WAF ---
step05: step05_waf_complete

step05_waf_complete: step05_waf_complete.c
	$(CC) $(CFLAGS) -o $@ $<

# --- Test (requires backend + WAF to be running) ---
test:
	@echo "Starting test suite..."
	@echo "Make sure step02_backend and step05_waf_complete are running!"
	@bash test_waf.sh

# --- Clean up binaries ---
clean:
	rm -f $(TARGETS)
	rm -f waf_log.txt
	@echo "Cleaned."

# --- Help ---
help:
	@echo ""
	@echo "WAF Project Build Targets:"
	@echo "  make all       — Build everything"
	@echo "  make step01    — Build Step 01 (basic TCP server)"
	@echo "  make step02    — Build Step 02 (backend + proxy)"
	@echo "  make step03    — Build Step 03 (HTTP parser proxy)"
	@echo "  make step04    — Build Step 04 (WAF with security rules)"
	@echo "  make step05    — Build Step 05 (complete WAF)"
	@echo "  make test      — Run test suite"
	@echo "  make clean     — Remove binaries"
	@echo ""
