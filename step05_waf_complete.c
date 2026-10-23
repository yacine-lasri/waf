/*
 * step05_waf_complete.c - Complete Web Application Firewall
 * =========================================================
 *
 * THE FINAL STEP: This is the polished, production-style WAF that brings
 * together everything we built in steps 01-04 and adds professional features:
 *
 *   Step 01: Basic TCP proxy (accept → forward → relay)
 *   Step 02: HTTP parsing (extract method, path, headers, body)
 *   Step 03: Security rule engine (SQLi, XSS detection)
 *   Step 04: Expanded rules (Path Traversal, Command Injection)
 *   Step 05: Rate limiting, file logging, statistics, error pages  ← YOU ARE HERE
 *
 * New features in this step:
 *   1. Rate Limiting   - Prevents brute-force and DoS by tracking request
 *                         counts per IP within a sliding time window.
 *   2. File Logging     - Every request is logged to "waf_log.txt" with a
 *                         timestamp, client IP, method, path, and verdict.
 *   3. Statistics       - Running counters of total/blocked/allowed/rate-limited
 *                         requests, printed every 10 requests as a summary.
 *   4. Error Pages      - Clean HTML responses for 403, 429, and 502 errors.
 *   5. Startup Banner   - Shows the active configuration at a glance.
 *
 * Compile:  gcc step05_waf_complete.c -o step05_waf_complete
 * Run:      ./step05_waf_complete
 * Test:     curl http://localhost:8080/
 *           curl "http://localhost:8080/search?q=1' UNION SELECT"
 *           curl "http://localhost:8080/<script>alert(1)</script>"
 *           curl "http://localhost:8080/../../etc/passwd"
 *           curl "http://localhost:8080/cmd?run=;cat /etc/passwd"
 *           (hit it 31+ times quickly to trigger rate limiting)
 *
 * Architecture:
 *
 *   Client ──► [ WAF :8080 ] ──► [ Backend :8888 ]
 *                  │                    │
 *                  ├─ Parse HTTP        │
 *                  ├─ Rate-limit check  │
 *                  ├─ Security rules    │
 *                  ├─ Log to file       │
 *                  └─ Forward if clean ─┘
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================
 *  CONFIGURATION - All tunables in one place
 * ============================================================
 * Change these #defines to adapt the WAF to your environment.
 * No recompilation of individual modules needed - it's all here.
 */

#define WAF_PORT        8080          /* Port the WAF listens on              */
#define BACKEND_PORT    8888          /* Port the real web server listens on  */
#define BACKEND_IP      "127.0.0.1"  /* Backend server IP address            */
#define BUFFER_SIZE     8192          /* Read buffer size for socket I/O      */
#define LOG_FILE        "waf_log.txt" /* Path to the request log file         */

/* --- Rate Limiting Configuration ---
 *
 * These three values control the rate limiter's behavior:
 *   MAX_TRACKED_IPS : How many unique client IPs we can track simultaneously.
 *                     If exceeded, oldest entries get overwritten (round-robin).
 *   RATE_WINDOW     : The time window (seconds) over which we count requests.
 *   MAX_REQUESTS    : Maximum requests allowed within one window per IP.
 *
 * Example: 30 requests per 60 seconds means a client can make roughly
 * one request every 2 seconds on average. Bursts are fine as long as
 * the total stays under 30 within any 60-second window.
 */
#define MAX_TRACKED_IPS 256
#define RATE_WINDOW     60           /* seconds */
#define MAX_REQUESTS    30           /* max requests per window per IP */

/* How often (in number of requests) to print the stats summary line. */
#define STATS_INTERVAL  10


/* ============================================================
 *  HTTP REQUEST STRUCTURE
 * ============================================================
 * Same structure we've used since step02. It holds all the pieces
 * of a parsed HTTP request so our rule engine can inspect them.
 */
struct http_request {
    char method[16];             /* GET, POST, PUT, DELETE, etc.         */
    char path[2048];             /* The request URI (e.g., /api/users)   */
    char version[16];            /* HTTP/1.1, HTTP/1.0                   */
    char host[256];              /* Value of the Host: header            */
    char content_type[256];      /* Value of Content-Type: header        */
    int  content_length;         /* Value of Content-Length: header      */
    char body[4096];             /* Request body (for POST/PUT etc.)     */
    char full_request[BUFFER_SIZE]; /* The original raw request text     */
    int  full_request_len;       /* Length of the raw request in bytes   */
};


/* ============================================================
 *  RATE LIMITER DATA STRUCTURES
 * ============================================================
 *
 * How the rate limiter works (a "fixed window" approach):
 *
 *   1. We maintain an array of ip_tracker structs, one per client IP.
 *   2. When a request arrives, we search for the client's IP in the array.
 *   3. If found, we check whether the current time is still within the
 *      same window (window_start + RATE_WINDOW > now).
 *      - If YES: increment request_count. If it exceeds MAX_REQUESTS,
 *                the request is rate-limited (429 response).
 *      - If NO:  the window has expired, so we reset window_start to now
 *                and request_count to 1. The client gets a fresh budget.
 *   4. If NOT found, we create a new entry with count=1 and window_start=now.
 *
 * This is a "fixed window" algorithm - simpler than a true sliding window,
 * but effective for learning. The trade-off is that a client could
 * theoretically make MAX_REQUESTS at the end of one window and MAX_REQUESTS
 * at the start of the next, getting 2x the limit in a short burst. A true
 * sliding window or token bucket would prevent this, but adds complexity.
 *
 * Memory management:
 *   - We use a static array of MAX_TRACKED_IPS entries.
 *   - ip_count tracks how many entries are in use.
 *   - If we run out of slots, we overwrite the oldest entry (the one with
 *     the smallest window_start). This is a simple eviction policy.
 */

struct ip_tracker {
    char   ip[INET_ADDRSTRLEN];  /* Client IP as a string, e.g., "192.168.1.5" */
    int    request_count;        /* How many requests this IP has made           */
    time_t window_start;         /* When the current counting window began      */
};

/* Global rate limiter state */
static struct ip_tracker ip_table[MAX_TRACKED_IPS];
static int ip_count = 0;


/* ============================================================
 *  REQUEST STATISTICS
 * ============================================================
 * Simple counters that give us a bird's-eye view of WAF activity.
 * Printed every STATS_INTERVAL requests so we can see trends.
 */
struct waf_stats {
    unsigned long total_requests;
    unsigned long blocked_requests;
    unsigned long allowed_requests;
    unsigned long rate_limited_requests;
};

/* Global stats - zeroed at startup */
static struct waf_stats stats = {0, 0, 0, 0};


/* Global log file handle - opened once at startup, used throughout */
static FILE *log_fp = NULL;


/* ============================================================
 *  UTILITY: Case-Insensitive Substring Search
 * ============================================================
 * We need case-insensitive matching because attackers try mixed-case
 * evasion: "UniOn SeLeCt", "<ScRiPt>", etc.
 *
 * This converts both haystack and needle to lowercase copies, then
 * uses strstr() on the copies. It's not the most efficient approach,
 * but it's clear and correct, which matters more for learning.
 */
static const char *case_insensitive_strstr(const char *haystack, const char *needle)
{
    size_t hay_len, need_len, i;
    char *hay_lower, *need_lower;
    char *found;

    if (!haystack || !needle) return NULL;

    hay_len  = strlen(haystack);
    need_len = strlen(needle);

    /* If needle is longer than haystack, it can't possibly match */
    if (need_len > hay_len) return NULL;

    /* Allocate lowercase copies on the stack for short strings,
     * or heap for longer ones. For simplicity, we always use the heap. */
    hay_lower  = malloc(hay_len + 1);
    need_lower = malloc(need_len + 1);
    if (!hay_lower || !need_lower) {
        free(hay_lower);
        free(need_lower);
        return NULL;
    }

    for (i = 0; i < hay_len; i++)
        hay_lower[i] = (char)tolower((unsigned char)haystack[i]);
    hay_lower[hay_len] = '\0';

    for (i = 0; i < need_len; i++)
        need_lower[i] = (char)tolower((unsigned char)needle[i]);
    need_lower[need_len] = '\0';

    found = strstr(hay_lower, need_lower);

    /* If found, calculate the position in the ORIGINAL haystack */
    if (found) {
        const char *result = haystack + (found - hay_lower);
        free(hay_lower);
        free(need_lower);
        return result;
    }

    free(hay_lower);
    free(need_lower);
    return NULL;
}


/* ============================================================
 *  HTTP REQUEST PARSER
 * ============================================================
 * Extracts the method, path, version, key headers, and body from
 * a raw HTTP request string. We've been using this since step02.
 *
 * Example raw request:
 *   "GET /api/users?id=5 HTTP/1.1\r\nHost: example.com\r\n\r\n"
 *
 * After parsing:
 *   method  = "GET"
 *   path    = "/api/users?id=5"
 *   version = "HTTP/1.1"
 *   host    = "example.com"
 */
static int parse_http_request(const char *raw, int raw_len, struct http_request *req)
{
    const char *line_end, *body_start, *header_start, *p;

    /* Zero out the struct so all strings start empty */
    memset(req, 0, sizeof(*req));

    /* Sanity check */
    if (!raw || raw_len <= 0) return -1;

    /* Save the full raw request for forwarding to the backend */
    if (raw_len >= BUFFER_SIZE) raw_len = BUFFER_SIZE - 1;
    memcpy(req->full_request, raw, raw_len);
    req->full_request_len = raw_len;

    /* --- Parse the Request Line ---
     * Format: "METHOD /path HTTP/version\r\n"
     * We find the first \r\n (or \n) to isolate this line. */
    line_end = strstr(raw, "\r\n");
    if (!line_end) line_end = strchr(raw, '\n');
    if (!line_end) return -1;

    /* Extract method: everything up to the first space */
    p = raw;
    {
        int i = 0;
        while (p < line_end && *p != ' ' && i < (int)sizeof(req->method) - 1) {
            req->method[i++] = *p++;
        }
        req->method[i] = '\0';
    }

    /* Skip the space between method and path */
    if (*p == ' ') p++;

    /* Extract path: everything up to the next space */
    {
        int i = 0;
        while (p < line_end && *p != ' ' && i < (int)sizeof(req->path) - 1) {
            req->path[i++] = *p++;
        }
        req->path[i] = '\0';
    }

    /* Skip space and extract HTTP version */
    if (*p == ' ') p++;
    {
        int i = 0;
        while (p < line_end && i < (int)sizeof(req->version) - 1) {
            req->version[i++] = *p++;
        }
        req->version[i] = '\0';
    }

    /* --- Parse Headers ---
     * Headers follow the request line, each ending with \r\n.
     * The header section ends with a blank line (\r\n\r\n). */
    header_start = line_end + 2;  /* Skip past the \r\n of request line */

    /* Find the Host header */
    {
        const char *host = case_insensitive_strstr(header_start, "Host:");
        if (host) {
            host += 5; /* Skip "Host:" */
            while (*host == ' ') host++; /* Skip whitespace */
            int i = 0;
            while (*host && *host != '\r' && *host != '\n' &&
                   i < (int)sizeof(req->host) - 1) {
                req->host[i++] = *host++;
            }
            req->host[i] = '\0';
        }
    }

    /* Find Content-Type header */
    {
        const char *ct = case_insensitive_strstr(header_start, "Content-Type:");
        if (ct) {
            ct += 13;
            while (*ct == ' ') ct++;
            int i = 0;
            while (*ct && *ct != '\r' && *ct != '\n' &&
                   i < (int)sizeof(req->content_type) - 1) {
                req->content_type[i++] = *ct++;
            }
            req->content_type[i] = '\0';
        }
    }

    /* Find Content-Length header */
    {
        const char *cl = case_insensitive_strstr(header_start, "Content-Length:");
        if (cl) {
            cl += 15;
            while (*cl == ' ') cl++;
            req->content_length = atoi(cl);
        }
    }

    /* --- Extract Body ---
     * The body starts after the blank line (\r\n\r\n) that separates
     * headers from the body. */
    body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        int body_len = raw_len - (int)(body_start - raw);
        if (body_len > 0) {
            if (body_len >= (int)sizeof(req->body))
                body_len = (int)sizeof(req->body) - 1;
            memcpy(req->body, body_start, body_len);
            req->body[body_len] = '\0';
        }
    }

    return 0;
}


/* ============================================================
 *  SECURITY RULE ENGINE
 * ============================================================
 * Four independent checks, each looking for a different class of
 * attack. Each returns NULL if the input is clean, or the name of
 * the matched pattern if an attack is detected.
 *
 * Why separate functions?
 *   - Each rule can be enabled/disabled independently
 *   - Easy to test each rule in isolation
 *   - Easy to add new rules without touching existing ones
 *   - Clean logging: we know exactly which rule triggered
 */

/* --- SQL Injection Detection ---
 *
 * SQL injection occurs when user input is embedded into SQL queries
 * without proper escaping. Attackers use keywords like UNION SELECT,
 * OR 1=1, and comment sequences to manipulate queries.
 *
 * We check for common SQL keywords and syntax patterns that should
 * never appear in legitimate web requests.
 */
static const char *check_sql_injection(const char *input)
{
    /* Array of patterns that strongly indicate SQL injection.
     * Each pattern is checked case-insensitively against the input.
     * We return the pattern name (not the actual search string) for
     * clear log messages. */
    static const struct {
        const char *pattern;   /* What to search for           */
        const char *name;      /* Human-readable name for logs */
    } sql_patterns[] = {
        { "union select",   "UNION SELECT"   },
        { "union all",      "UNION ALL"      },
        { "' or '1'='1",    "OR 1=1"         },
        { "' or 1=1",       "OR 1=1"         },
        { "or 1=1--",       "OR 1=1--"       },
        { "'; drop table",  "DROP TABLE"     },
        { "drop table",     "DROP TABLE"     },
        { "'; --",          "SQL Comment"    },
        { "1'; --",         "SQL Comment"    },
        { "select * from",  "SELECT FROM"    },
        { "insert into",    "INSERT INTO"    },
        { "delete from",    "DELETE FROM"    },
        { "update%20set",   "UPDATE SET"     },
        { "having 1=1",     "HAVING 1=1"     },
        { "order by 1",     "ORDER BY"       },
        { "benchmark(",     "BENCHMARK"      },
        { "sleep(",         "SLEEP()"        },
        { "waitfor delay",  "WAITFOR DELAY"  },
        { "load_file(",     "LOAD_FILE"      },
        { "into outfile",   "INTO OUTFILE"   },
        { "into dumpfile",  "INTO DUMPFILE"  },
        { NULL, NULL }
    };

    int i;
    if (!input) return NULL;

    for (i = 0; sql_patterns[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, sql_patterns[i].pattern)) {
            return sql_patterns[i].name;
        }
    }

    return NULL; /* Clean - no SQL injection detected */
}


/* --- XSS (Cross-Site Scripting) Detection ---
 *
 * XSS attacks inject client-side scripts into web pages viewed by
 * other users. The injected scripts can steal cookies, redirect
 * users, or deface pages.
 *
 * We look for HTML/JavaScript patterns that should never appear in
 * normal request parameters.
 */
static const char *check_xss(const char *input)
{
    static const struct {
        const char *pattern;
        const char *name;
    } xss_patterns[] = {
        { "<script",        "<script>"        },
        { "</script",       "</script>"       },
        { "javascript:",    "javascript:"     },
        { "onerror=",       "onerror="        },
        { "onload=",        "onload="         },
        { "onclick=",       "onclick="        },
        { "onmouseover=",   "onmouseover="    },
        { "onfocus=",       "onfocus="        },
        { "onblur=",        "onblur="         },
        { "eval(",          "eval()"          },
        { "document.cookie","document.cookie" },
        { "document.write", "document.write"  },
        { "window.location","window.location" },
        { "alert(",         "alert()"         },
        { "<iframe",        "<iframe>"        },
        { "<object",        "<object>"        },
        { "<embed",         "<embed>"         },
        { "<svg",           "<svg>"           },
        { "expression(",    "expression()"    },
        { "vbscript:",      "vbscript:"       },
        { NULL, NULL }
    };

    int i;
    if (!input) return NULL;

    for (i = 0; xss_patterns[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, xss_patterns[i].pattern)) {
            return xss_patterns[i].name;
        }
    }

    return NULL;
}


/* --- Path Traversal Detection ---
 *
 * Path traversal attacks try to escape the web root directory to
 * access files elsewhere on the server's filesystem. They use
 * sequences like "../" or "/etc/passwd" to navigate up the
 * directory tree.
 *
 * This is particularly dangerous because it can expose:
 *   - /etc/passwd (user accounts)
 *   - /etc/shadow (password hashes)
 *   - Application configuration files with credentials
 *   - Source code
 */
static const char *check_path_traversal(const char *input)
{
    static const struct {
        const char *pattern;
        const char *name;
    } traversal_patterns[] = {
        { "../",            "../"             },
        { "..\\",           "..\\"            },
        { "%2e%2e%2f",      "encoded ../"     },  /* URL-encoded ../ */
        { "%2e%2e/",        "encoded ../"     },
        { "..%2f",          "encoded ../"     },
        { "%2e%2e%5c",      "encoded ..\\"    },  /* URL-encoded ..\ */
        { "/etc/passwd",    "/etc/passwd"     },
        { "/etc/shadow",    "/etc/shadow"     },
        { "/proc/self",     "/proc/self"      },
        { "c:\\windows",    "c:\\windows"     },
        { "c:/windows",     "c:/windows"      },
        { "boot.ini",       "boot.ini"        },
        { "win.ini",        "win.ini"         },
        { NULL, NULL }
    };

    int i;
    if (!input) return NULL;

    for (i = 0; traversal_patterns[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, traversal_patterns[i].pattern)) {
            return traversal_patterns[i].name;
        }
    }

    return NULL;
}


/* --- Command Injection Detection ---
 *
 * Command injection occurs when user input is passed to a system
 * shell (via system(), popen(), exec(), etc.) without sanitization.
 * Attackers use shell metacharacters to chain additional commands.
 *
 * The semicolon (;), pipe (|), backtick (`), and $() are the most
 * common injection vectors because they allow command chaining
 * in both bash and sh.
 */
static const char *check_command_injection(const char *input)
{
    static const struct {
        const char *pattern;
        const char *name;
    } cmd_patterns[] = {
        { ";cat ",          ";cat"            },
        { ";ls ",           ";ls"             },
        { ";ls/",           ";ls/"            },
        { "|cat ",          "|cat"            },
        { "|ls ",           "|ls"             },
        { "`cat ",          "`cat`"           },
        { "`ls ",           "`ls`"            },
        { "$(cat ",         "$(cat)"          },
        { "$(ls ",          "$(ls)"           },
        { ";rm ",           ";rm"             },
        { ";rm -",          ";rm -rf"         },
        { "|rm ",           "|rm"             },
        { ";wget ",         ";wget"           },
        { ";curl ",         ";curl"           },
        { "|wget ",         "|wget"           },
        { "|curl ",         "|curl"           },
        { ";nc ",           ";nc (netcat)"    },
        { ";bash ",         ";bash"           },
        { ";sh ",           ";sh"             },
        { "|bash ",         "|bash"           },
        { "|sh ",           "|sh"             },
        { "/bin/sh",        "/bin/sh"         },
        { "/bin/bash",      "/bin/bash"       },
        { "&&cat ",         "&&cat"           },
        { "&&ls ",          "&&ls"            },
        { "||cat ",         "||cat"           },
        { "||ls ",          "||ls"            },
        { NULL, NULL }
    };

    int i;
    if (!input) return NULL;

    for (i = 0; cmd_patterns[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, cmd_patterns[i].pattern)) {
            return cmd_patterns[i].name;
        }
    }

    return NULL;
}


/* ============================================================
 *  COMBINED SECURITY CHECK
 * ============================================================
 * Runs ALL security rules against the relevant parts of the HTTP
 * request. We check:
 *   - The path (URL)   → most attacks arrive via URL parameters
 *   - The body         → POST-based attacks (login forms, APIs)
 *   - The Host header  → host header injection (less common)
 *
 * Returns NULL if the request is clean.
 * Returns a descriptive string like "SQL Injection: UNION SELECT"
 * if an attack is detected.
 *
 * The returned string is a static buffer - NOT dynamically allocated.
 * This is fine because we use it immediately and only one request
 * is processed at a time (single-threaded).
 */
static const char *run_security_checks(const struct http_request *req)
{
    const char *match;
    static char result[256]; /* Static buffer for the result string */

    /* Surfaces to inspect: path, body, and host header.
     * We combine them into an array to avoid repeating the same
     * check logic four times. */
    const char *surfaces[] = { req->path, req->body, req->host };
    const char *surface_names[] = { "URL", "Body", "Host" };
    int num_surfaces = 3;
    int s;

    for (s = 0; s < num_surfaces; s++) {
        /* Skip empty surfaces */
        if (!surfaces[s] || surfaces[s][0] == '\0') continue;

        /* Run each rule engine against this surface */
        match = check_sql_injection(surfaces[s]);
        if (match) {
            snprintf(result, sizeof(result), "SQL Injection: %s [in %s]",
                     match, surface_names[s]);
            return result;
        }

        match = check_xss(surfaces[s]);
        if (match) {
            snprintf(result, sizeof(result), "XSS: %s [in %s]",
                     match, surface_names[s]);
            return result;
        }

        match = check_path_traversal(surfaces[s]);
        if (match) {
            snprintf(result, sizeof(result), "Path Traversal: %s [in %s]",
                     match, surface_names[s]);
            return result;
        }

        match = check_command_injection(surfaces[s]);
        if (match) {
            snprintf(result, sizeof(result), "Command Injection: %s [in %s]",
                     match, surface_names[s]);
            return result;
        }
    }

    return NULL; /* All clear - no threats detected */
}


/* ============================================================
 *  RATE LIMITER
 * ============================================================
 *
 * The rate limiter prevents abuse by tracking how many requests each
 * client IP has sent within a time window. Here's the algorithm:
 *
 *   ┌─────────────────────────────────────────────────────────┐
 *   │  Time ──────────────────────────────►                   │
 *   │                                                         │
 *   │  Window 1:  [────── 60 seconds ──────]                  │
 *   │   requests:  ||||| |||| ||| (13 requests - OK)          │
 *   │                                                         │
 *   │  Window 2:           [────── 60 seconds ──────]         │
 *   │   requests:  (window expired, counter resets to 0)      │
 *   │              ||||| ||||| ||||| ||||| ||||| ||||||        │
 *   │              (31 requests - BLOCKED after 30th!)        │
 *   └─────────────────────────────────────────────────────────┘
 *
 * Key decisions and trade-offs:
 *
 * 1. Fixed Window vs. Sliding Window:
 *    We use a FIXED window for simplicity. When the window expires,
 *    the counter resets entirely. A sliding window would be more
 *    precise but requires storing individual request timestamps.
 *
 * 2. Static Array vs. Hash Table:
 *    We use a simple array with linear search. For 256 entries max,
 *    this is fast enough. A hash table would be better for thousands
 *    of tracked IPs, but adds complexity.
 *
 * 3. Eviction Policy:
 *    When the array is full, we evict the entry with the oldest
 *    window_start time. This means long-idle IPs get replaced first.
 *
 * Returns:
 *   0 = Request is within limits (allowed)
 *   1 = Request exceeds the rate limit (should be blocked with 429)
 */
static int check_rate_limit(const char *client_ip)
{
    time_t now = time(NULL);
    int i;

    /* --- Step 1: Search for existing entry for this IP ---
     * Linear scan through the tracking table. For MAX_TRACKED_IPS=256,
     * this is at most 256 string comparisons - trivially fast. */
    for (i = 0; i < ip_count; i++) {
        if (strcmp(ip_table[i].ip, client_ip) == 0) {
            /* Found this IP in our tracking table */

            /* Check if the current window has expired */
            if (now - ip_table[i].window_start >= RATE_WINDOW) {
                /* Window expired! Reset the counter.
                 * The client gets a fresh budget of MAX_REQUESTS. */
                ip_table[i].window_start = now;
                ip_table[i].request_count = 1;
                return 0; /* Allowed - fresh window */
            }

            /* Window is still active - increment the counter */
            ip_table[i].request_count++;

            /* Check if the limit has been exceeded */
            if (ip_table[i].request_count > MAX_REQUESTS) {
                /* Rate limit exceeded!
                 * We still increment the counter (to show in logs how
                 * far over the limit they are) but return 1 to indicate
                 * this request should be blocked. */
                return 1; /* BLOCKED - too many requests */
            }

            return 0; /* Allowed - within limits */
        }
    }

    /* --- Step 2: IP not found - create a new entry ---
     *
     * If the table isn't full, just append. If it IS full, we need
     * to evict someone. We choose the entry with the oldest
     * window_start, since that IP has been idle the longest. */

    if (ip_count < MAX_TRACKED_IPS) {
        /* There's room - add to the end of the table */
        i = ip_count;
        ip_count++;
    } else {
        /* Table is full - find the oldest entry to evict.
         * "Oldest" means the smallest window_start value,
         * i.e., the IP that started its window longest ago. */
        int oldest_idx = 0;
        time_t oldest_time = ip_table[0].window_start;

        for (i = 1; i < MAX_TRACKED_IPS; i++) {
            if (ip_table[i].window_start < oldest_time) {
                oldest_time = ip_table[i].window_start;
                oldest_idx = i;
            }
        }
        i = oldest_idx;
        /* Note: we're overwriting this entry entirely below */
    }

    /* Initialize the new entry */
    strncpy(ip_table[i].ip, client_ip, INET_ADDRSTRLEN - 1);
    ip_table[i].ip[INET_ADDRSTRLEN - 1] = '\0';
    ip_table[i].request_count = 1;
    ip_table[i].window_start  = now;

    return 0; /* Allowed - first request in this window */
}


/* ============================================================
 *  REQUEST LOGGING
 * ============================================================
 * Logs each request to both the console (stdout) and the log file.
 *
 * Log format:
 *   [YYYY-MM-DD HH:MM:SS] <IP> <METHOD> <PATH> <VERDICT> [(reason)]
 *
 * Examples:
 *   [2024-01-15 14:30:22] 192.168.1.5 GET /api/users ALLOWED
 *   [2024-01-15 14:30:23] 10.0.0.1 POST /login BLOCKED (SQL Injection: UNION SELECT)
 *   [2024-01-15 14:30:24] 172.16.0.1 GET / RATE-LIMITED
 *
 * The log file is opened in append mode at startup, so logs persist
 * across WAF restarts. We flush after every write to ensure logs
 * are saved even if the WAF crashes.
 */
static void log_request(const char *client_ip,
                        const char *method,
                        const char *path,
                        const char *verdict,
                        const char *reason)
{
    time_t now;
    struct tm *tm_info;
    char timestamp[64];

    /* Get the current time and format it */
    now = time(NULL);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Print to console (stdout) */
    if (reason && reason[0] != '\0') {
        printf("  [%s] %s %s %s %s (%s)\n",
               timestamp, client_ip, method, path, verdict, reason);
    } else {
        printf("  [%s] %s %s %s %s\n",
               timestamp, client_ip, method, path, verdict);
    }

    /* Write to log file */
    if (log_fp) {
        if (reason && reason[0] != '\0') {
            fprintf(log_fp, "[%s] %s %s %s %s (%s)\n",
                    timestamp, client_ip, method, path, verdict, reason);
        } else {
            fprintf(log_fp, "[%s] %s %s %s %s\n",
                    timestamp, client_ip, method, path, verdict);
        }
        /* Flush immediately so logs survive crashes */
        fflush(log_fp);
    }
}


/* ============================================================
 *  STATISTICS PRINTER
 * ============================================================
 * Prints a summary of WAF activity every STATS_INTERVAL requests.
 * This gives us a quick health check without reading the full log.
 */
static void print_stats_if_needed(void)
{
    if (stats.total_requests > 0 && stats.total_requests % STATS_INTERVAL == 0) {
        printf("\n  ┌──── WAF Stats (after %lu requests) ────┐\n",
               stats.total_requests);
        printf("  │  Allowed      : %-10lu              │\n",
               stats.allowed_requests);
        printf("  │  Blocked      : %-10lu              │\n",
               stats.blocked_requests);
        printf("  │  Rate-Limited : %-10lu              │\n",
               stats.rate_limited_requests);
        printf("  └─────────────────────────────────────────┘\n\n");
    }
}


/* ============================================================
 *  ERROR RESPONSE PAGES
 * ============================================================
 * Pre-built HTML responses for different error conditions. Each
 * function writes a complete HTTP response (status line + headers +
 * HTML body) to the client socket.
 *
 * Why not just send "403 Forbidden" as plain text?
 * Because browsers render HTML nicely, and a clean error page looks
 * professional. It also helps developers understand WHY their
 * request was blocked.
 */

/* --- 403 Forbidden: Request blocked by WAF rules --- */
static void send_403_blocked(int client_fd, const char *rule_name)
{
    char body[2048];
    char response[4096];
    int body_len;

    body_len = snprintf(body, sizeof(body),
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>403 - Blocked by WAF</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; "
        "padding: 50px; background: #fef2f2;\">\n"
        "  <h1 style=\"color: #dc2626;\">&#x1F6E1; 403 - Blocked by WAF</h1>\n"
        "  <p style=\"color: #991b1b; font-size: 18px;\">Your request was "
        "blocked by the Web Application Firewall.</p>\n"
        "  <div style=\"background: #fee2e2; border: 1px solid #fca5a5; "
        "border-radius: 8px; padding: 15px; display: inline-block;\">\n"
        "    <strong>Rule triggered:</strong> %s\n"
        "  </div>\n"
        "  <p style=\"color: #6b7280; margin-top: 30px; font-size: 14px;\">"
        "If you believe this is an error, please contact the site "
        "administrator.</p>\n"
        "</body>\n"
        "</html>\n",
        rule_name ? rule_name : "Unknown");

    snprintf(response, sizeof(response),
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, body);

    send(client_fd, response, strlen(response), 0);
}


/* --- 429 Too Many Requests: Client exceeded rate limit --- */
static void send_429_rate_limited(int client_fd)
{
    const char *body =
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>429 - Too Many Requests</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; "
        "padding: 50px; background: #fffbeb;\">\n"
        "  <h1 style=\"color: #d97706;\">&#x23F3; 429 - Too Many Requests</h1>\n"
        "  <p style=\"color: #92400e; font-size: 18px;\">You are sending "
        "requests too quickly. Please slow down.</p>\n"
        "  <div style=\"background: #fef3c7; border: 1px solid #fcd34d; "
        "border-radius: 8px; padding: 15px; display: inline-block;\">\n"
        "    <strong>Limit:</strong> " /* Stringify the limits inline */
        "%d requests per %d seconds\n"
        "  </div>\n"
        "  <p style=\"color: #6b7280; margin-top: 30px; font-size: 14px;\">"
        "Wait a moment and try again.</p>\n"
        "</body>\n"
        "</html>\n";

    char body_buf[2048];
    char response[4096];
    int body_len;

    body_len = snprintf(body_buf, sizeof(body_buf), body,
                        MAX_REQUESTS, RATE_WINDOW);

    snprintf(response, sizeof(response),
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Retry-After: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, RATE_WINDOW, body_buf);

    send(client_fd, response, strlen(response), 0);
}


/* --- 502 Bad Gateway: Backend server is unreachable --- */
static void send_502_bad_gateway(int client_fd)
{
    const char *body =
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>502 - Bad Gateway</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; "
        "padding: 50px; background: #f3f4f6;\">\n"
        "  <h1 style=\"color: #4b5563;\">&#x26A0; 502 - Bad Gateway</h1>\n"
        "  <p style=\"color: #6b7280; font-size: 18px;\">The backend server "
        "is not responding.</p>\n"
        "  <div style=\"background: #e5e7eb; border: 1px solid #d1d5db; "
        "border-radius: 8px; padding: 15px; display: inline-block;\">\n"
        "    <strong>Backend:</strong> " BACKEND_IP ":%d\n"
        "  </div>\n"
        "  <p style=\"color: #6b7280; margin-top: 30px; font-size: 14px;\">"
        "Make sure the backend server is running and try again.</p>\n"
        "</body>\n"
        "</html>\n";

    char body_buf[2048];
    char response[4096];
    int body_len;

    body_len = snprintf(body_buf, sizeof(body_buf), body, BACKEND_PORT);

    snprintf(response, sizeof(response),
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, body_buf);

    send(client_fd, response, strlen(response), 0);
}


/* ============================================================
 *  BACKEND FORWARDING
 * ============================================================
 * Connects to the backend server, sends the original request,
 * receives the response, and relays it back to the client.
 *
 * Returns:
 *   0 on success
 *  -1 if the backend is unreachable (triggers 502 response)
 */
static int forward_to_backend(int client_fd, const struct http_request *req)
{
    int backend_fd;
    struct sockaddr_in backend_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes;

    /* Create a socket to connect to the backend */
    backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_fd < 0) {
        perror("  [ERROR] Backend socket creation failed");
        return -1;
    }

    /* Set up the backend address */
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port   = htons(BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_IP, &backend_addr.sin_addr);

    /* Connect to the backend server */
    if (connect(backend_fd, (struct sockaddr *)&backend_addr,
                sizeof(backend_addr)) < 0) {
        /* Backend is down or refusing connections */
        close(backend_fd);
        return -1;
    }

    /* Forward the original request exactly as received.
     * We send the full raw request to preserve all headers and body
     * content. The backend sees exactly what the client sent. */
    if (send(backend_fd, req->full_request, req->full_request_len, 0) < 0) {
        perror("  [ERROR] Failed to send to backend");
        close(backend_fd);
        return -1;
    }

    /* Relay the backend's response back to the client.
     * We read in a loop because the response might be larger than
     * our buffer, requiring multiple reads. */
    while ((bytes = recv(backend_fd, buffer, sizeof(buffer), 0)) > 0) {
        /* Send each chunk to the client immediately.
         * In a production WAF, we might buffer the entire response
         * to inspect it (e.g., for data leakage prevention). */
        if (send(client_fd, buffer, bytes, 0) < 0) {
            perror("  [ERROR] Failed to relay response to client");
            break;
        }
    }

    close(backend_fd);
    return 0;
}


/* ============================================================
 *  REQUEST HANDLER
 * ============================================================
 * The main processing pipeline for each incoming request.
 * This is where all the pieces come together:
 *
 *   1. Receive raw data from the client socket
 *   2. Parse the HTTP request
 *   3. Check rate limits    → 429 if exceeded
 *   4. Run security rules   → 403 if attack detected
 *   5. Forward to backend   → 502 if backend is down
 *   6. Log the result
 *   7. Update statistics
 *
 * Each step is clearly separated so you can follow the flow.
 */
static void handle_client(int client_fd, const char *client_ip)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    struct http_request req;
    const char *threat;

    /* --- Step 1: Receive the raw HTTP request --- */
    bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        /* Client disconnected or error - nothing to process */
        close(client_fd);
        return;
    }
    buffer[bytes_received] = '\0'; /* Null-terminate for string functions */

    /* --- Step 2: Parse the HTTP request --- */
    if (parse_http_request(buffer, (int)bytes_received, &req) < 0) {
        /* Failed to parse - not a valid HTTP request */
        printf("  [WARN] Malformed request from %s\n", client_ip);
        close(client_fd);
        return;
    }

    /* Update total request counter */
    stats.total_requests++;

    printf("\n  [REQUEST #%lu] %s %s from %s\n",
           stats.total_requests, req.method, req.path, client_ip);

    /* --- Step 3: Check rate limit ---
     * This MUST come before security checks because:
     *   a) Rate limiting is cheaper than running all pattern checks
     *   b) An attacker sending thousands of SQLi attempts gets
     *      rate-limited, reducing the load on the rule engine
     *   c) We want to count ALL requests toward the rate limit,
     *      including malicious ones
     */
    if (check_rate_limit(client_ip)) {
        /* Rate limit exceeded - block with 429 */
        printf("  [RATE-LIMITED] %s exceeded %d requests in %d seconds\n",
               client_ip, MAX_REQUESTS, RATE_WINDOW);

        log_request(client_ip, req.method, req.path, "RATE-LIMITED", NULL);
        send_429_rate_limited(client_fd);

        stats.rate_limited_requests++;
        print_stats_if_needed();

        close(client_fd);
        return;
    }

    /* --- Step 4: Run security rules ---
     * Check the request against all four rule categories. */
    threat = run_security_checks(&req);
    if (threat) {
        /* Attack detected - block with 403 */
        printf("  [BLOCKED] Threat detected: %s\n", threat);

        log_request(client_ip, req.method, req.path, "BLOCKED", threat);
        send_403_blocked(client_fd, threat);

        stats.blocked_requests++;
        print_stats_if_needed();

        close(client_fd);
        return;
    }

    /* --- Step 5: Forward to backend ---
     * Request passed all checks - forward it to the real server. */
    printf("  [ALLOWED] Forwarding to backend %s:%d\n", BACKEND_IP, BACKEND_PORT);

    if (forward_to_backend(client_fd, &req) < 0) {
        /* Backend is unreachable */
        printf("  [ERROR] Backend %s:%d unreachable, sending 502\n",
               BACKEND_IP, BACKEND_PORT);

        log_request(client_ip, req.method, req.path, "ALLOWED", "backend unreachable (502)");
        send_502_bad_gateway(client_fd);
    } else {
        /* Success - request was forwarded and response was relayed */
        log_request(client_ip, req.method, req.path, "ALLOWED", NULL);
    }

    stats.allowed_requests++;
    print_stats_if_needed();

    close(client_fd);
}


/* ============================================================
 *  STARTUP BANNER
 * ============================================================
 * Displays the WAF configuration when it starts up. This helps
 * operators quickly verify the settings are correct.
 */
static void print_banner(void)
{
    printf("\n");
    printf("  ============================================\n");
    printf("         WAF - Web Application Firewall       \n");
    printf("  ============================================\n");
    printf("    Listening on    : port %d\n", WAF_PORT);
    printf("    Backend server  : %s:%d\n", BACKEND_IP, BACKEND_PORT);
    printf("    Rate limit      : %d req/%ds per IP\n", MAX_REQUESTS, RATE_WINDOW);
    printf("    Log file        : %s\n", LOG_FILE);
    printf("    Rules active    : SQLi, XSS, Path Traversal, Command Injection\n");
    printf("  ============================================\n");
    printf("\n");
    printf("  Waiting for connections...\n");
}


/* ============================================================
 *  MAIN - The WAF Entry Point
 * ============================================================
 * Sets up the listening socket, opens the log file, prints the
 * banner, and enters the main accept loop.
 *
 * The accept loop is single-threaded and blocking: it handles one
 * request at a time. For a learning project this is fine. A
 * production WAF would use threads, epoll, or an event loop.
 */
int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char client_ip[INET_ADDRSTRLEN];
    int opt = 1;

    /* --- Open the log file in append mode ---
     * Append mode ("a") means we add to the existing log instead of
     * overwriting it. This preserves logs across restarts. */
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        fprintf(stderr, "  [WARNING] Could not open %s for writing: %s\n",
                LOG_FILE, strerror(errno));
        fprintf(stderr, "  [WARNING] File logging disabled, continuing with console only.\n");
        /* We continue without file logging rather than exiting.
         * The WAF is still useful without it. */
    }

    /* --- Create the server socket ---
     * AF_INET  = IPv4
     * SOCK_STREAM = TCP (reliable, ordered byte stream)
     * 0 = let the OS pick the protocol (TCP for SOCK_STREAM) */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("  [FATAL] Socket creation failed");
        if (log_fp) fclose(log_fp);
        return 1;
    }

    /* SO_REUSEADDR lets us restart the WAF immediately without waiting
     * for the OS to release the port (TIME_WAIT state). Essential
     * during development when you're constantly restarting. */
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* --- Bind to our port ---
     * INADDR_ANY means we listen on all network interfaces
     * (localhost, ethernet, WiFi, etc.) */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(WAF_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("  [FATAL] Bind failed");
        fprintf(stderr, "  Is port %d already in use? Try: lsof -i :%d\n",
                WAF_PORT, WAF_PORT);
        close(server_fd);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    /* --- Start listening for connections ---
     * Backlog of 10 means up to 10 connections can queue while we're
     * busy handling another request. Beyond that, new connections
     * are refused by the OS. */
    if (listen(server_fd, 10) < 0) {
        perror("  [FATAL] Listen failed");
        close(server_fd);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    /* Show the startup banner with all configuration details */
    print_banner();

    /* --- Main Accept Loop ---
     * This is the heart of the WAF. We sit here forever, accepting
     * one connection at a time and processing it through our pipeline.
     *
     * For each connection:
     *   1. accept() blocks until a client connects
     *   2. We extract the client's IP address for logging
     *   3. handle_client() does all the work
     *   4. The client socket is closed inside handle_client()
     *   5. We loop back and wait for the next connection
     *
     * This single-threaded model is simple and correct, but it means
     * only one request is processed at a time. While we're handling
     * one client, other clients queue in the listen backlog.
     */
    while (1) {
        client_len = sizeof(client_addr);

        /* accept() extracts the first pending connection from the
         * listen queue and creates a new socket for it. The original
         * server_fd keeps listening for more connections. */
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
                           &client_len);
        if (client_fd < 0) {
            perror("  [ERROR] Accept failed");
            continue; /* Don't crash - just skip this connection */
        }

        /* Convert the client's binary IP address to a human-readable
         * string like "192.168.1.5" for logging and rate limiting. */
        inet_ntop(AF_INET, &client_addr.sin_addr,
                  client_ip, sizeof(client_ip));

        /* Process this request through the full WAF pipeline */
        handle_client(client_fd, client_ip);
    }

    /* We never actually reach here (infinite loop above), but good
     * practice to clean up anyway. If we add a signal handler for
     * graceful shutdown later, this code would execute. */
    close(server_fd);
    if (log_fp) fclose(log_fp);

    return 0;
}
