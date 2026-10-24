/*
 * step05_waf_complete.c - Complete Web Application Firewall
 * =========================================================
 *
 * THE FINAL STEP: A production-style, resilient WAF in C.
 *
 * Capabilities:
 *   1. Full TCP stream buffering (handles split headers and delayed POST bodies)
 *   2. Socket read timeouts (slow client DoS protection)
 *   3. Deep inspection surfaces: URL, Query, Body, User-Agent, Referer, Cookie
 *   4. URL Percent-Decoding and Double-Decoding evasion protection
 *   5. SQL comment-stripping (defeats inline SQL comment evasions)
 *   6. Robust HTTP parsing: rejects duplicate/conflicting Content-Length (smuggling)
 *   7. URI length validation: rejects oversized URLs with 414 URI Too Long
 *   8. Sliding window rate limiter (429 Too Many Requests)
 *   9. File logging with persistent append and immediate flush (waf_log.txt)
 *  10. Live telemetry statistics
 *
 * Architecture:
 *   Client ---> [ WAF :8080 ] ---> [ Backend :8888 ]
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
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================
 *  CONFIGURATION
 * ============================================================
 */
#define WAF_PORT        8080          /* WAF listener port                    */
#define BACKEND_PORT    8888          /* Target backend web server port       */
#define BACKEND_IP      "127.0.0.1"  /* Target backend IP address            */
#define BUFFER_SIZE     131072        /* 128 KB buffer for large payloads     */
#define MAX_PATH_LEN    4096          /* Max allowed URI length               */
#define LOG_FILE        "waf_log.txt" /* Request audit log path               */
#define CLIENT_TIMEOUT  3             /* Socket read timeout in seconds       */
#define TOTAL_REQUEST_DEADLINE 3.0    /* Maximum total request lifetime (s)   */

/* --- Rate Limiting Configuration --- */
#define MAX_TRACKED_IPS 256
#define RATE_WINDOW     60           /* Time window in seconds               */
#define MAX_REQUESTS    100          /* Max requests per window per IP       */
#define STATS_INTERVAL  10           /* Stats print interval (requests)      */

/* ============================================================
 *  HTTP REQUEST STRUCTURE
 * ============================================================
 */
struct http_request {
    char method[16];
    char path[MAX_PATH_LEN];
    char version[16];
    char host[256];
    char content_type[256];
    char user_agent[512];
    char referer[512];
    char cookie[1024];
    char headers_raw[8192];
    int  content_length;
    int  duplicate_content_length;
    char body[65536];
    int  body_len;
    char full_request[BUFFER_SIZE];
    int  full_request_len;
};

/* Global static request struct (single-threaded accept loop) */
static struct http_request g_req;

/* ============================================================
 *  RATE LIMITER DATA STRUCTURES
 * ============================================================
 */
struct ip_tracker {
    char   ip[INET_ADDRSTRLEN];
    int    request_count;
    time_t window_start;
};

static struct ip_tracker ip_table[MAX_TRACKED_IPS];
static int ip_count = 0;

/* ============================================================
 *  REQUEST STATISTICS
 * ============================================================
 */
struct waf_stats {
    unsigned long total_requests;
    unsigned long blocked_requests;
    unsigned long allowed_requests;
    unsigned long rate_limited_requests;
};

static struct waf_stats stats = {0, 0, 0, 0};
static FILE *log_fp = NULL;

/* ============================================================
 *  UTILITY FUNCTIONS: Normalization & Decoding
 * ============================================================
 */

/* Case-insensitive substring search */
static const char *case_insensitive_strstr(const char *haystack, const char *needle)
{
    size_t hay_len, need_len, i;
    char *hay_lower, *need_lower;
    char *found;

    if (!haystack || !needle) return NULL;

    hay_len  = strlen(haystack);
    need_len = strlen(needle);
    if (need_len > hay_len) return NULL;

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

/* Hex conversion for percent-decoding */
static int hex_to_int(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* URL percent-decoding (converts %20 -> space, + -> space, %27 -> ', etc.) */
static void url_decode(char *dst, const char *src, size_t dst_len)
{
    size_t d = 0;
    if (!dst || !src || dst_len == 0) return;

    while (*src && d + 1 < dst_len) {
        if (*src == '%' && src[1] && src[2]) {
            int h1 = hex_to_int(src[1]);
            int h2 = hex_to_int(src[2]);
            if (h1 >= 0 && h2 >= 0) {
                dst[d++] = (char)((h1 << 4) | h2);
                src += 3;
                continue;
            }
        } else if (*src == '+') {
            dst[d++] = ' ';
            src++;
            continue;
        }
        dst[d++] = *src++;
    }
    dst[d] = '\0';
}

/* Strip SQL block comments: replaces / * ... * / with a single space or empty */
static void strip_sql_comments(char *dst, const char *src, size_t dst_len, int insert_space)
{
    size_t d = 0;
    if (!dst || !src || dst_len == 0) return;

    while (*src && d + 1 < dst_len) {
        if (src[0] == '/' && src[1] == '*') {
            const char *end = strstr(src + 2, "*/");
            if (end) {
                if (insert_space) {
                    dst[d++] = ' ';
                }
                src = end + 2;
                continue;
            }
        }
        dst[d++] = *src++;
    }
    dst[d] = '\0';
}

/* ============================================================
 *  HTTP REQUEST PARSER
 * ============================================================
 * Returns:
 *   0 on success
 *  -1 on malformed request
 *  -2 on URI Too Long (> MAX_PATH_LEN)
 *  -3 on conflicting duplicate Content-Length headers
 */
static int parse_http_request(const char *raw, int raw_len, struct http_request *req)
{
    const char *line_end, *body_start, *header_start, *p;

    memset(req, 0, sizeof(*req));
    if (!raw || raw_len <= 0) return -1;

    if (raw_len >= BUFFER_SIZE) raw_len = BUFFER_SIZE - 1;
    memcpy(req->full_request, raw, raw_len);
    req->full_request[raw_len] = '\0';
    req->full_request_len = raw_len;

    /* Parse request line */
    line_end = strstr(raw, "\r\n");
    if (!line_end) line_end = strchr(raw, '\n');
    if (!line_end) return -1;

    /* Method */
    p = raw;
    {
        int i = 0;
        while (p < line_end && *p != ' ' && i < (int)sizeof(req->method) - 1) {
            req->method[i++] = *p++;
        }
        req->method[i] = '\0';
    }

    if (*p == ' ') p++;

    /* Path */
    {
        int i = 0;
        while (p < line_end && *p != ' ') {
            if (i >= (int)sizeof(req->path) - 1) {
                return -2; /* URI Too Long */
            }
            req->path[i++] = *p++;
        }
        req->path[i] = '\0';
    }

    if (*p == ' ') p++;

    /* Version */
    {
        int i = 0;
        while (p < line_end && i < (int)sizeof(req->version) - 1) {
            req->version[i++] = *p++;
        }
        req->version[i] = '\0';
    }

    /* Headers */
    header_start = line_end + 2;
    body_start = strstr(raw, "\r\n\r\n");
    if (!body_start) {
        body_start = strstr(raw, "\n\n");
        if (body_start) body_start += 2;
    } else {
        body_start += 4;
    }

    if (header_start && body_start && body_start >= header_start) {
        int h_len = (int)(body_start - header_start);
        if (h_len >= (int)sizeof(req->headers_raw))
            h_len = (int)sizeof(req->headers_raw) - 1;
        memcpy(req->headers_raw, header_start, h_len);
        req->headers_raw[h_len] = '\0';
    }

    /* Extract Host */
    {
        const char *h = case_insensitive_strstr(header_start, "Host:");
        if (h) {
            h += 5;
            while (*h == ' ') h++;
            int i = 0;
            while (*h && *h != '\r' && *h != '\n' && i < (int)sizeof(req->host) - 1)
                req->host[i++] = *h++;
            req->host[i] = '\0';
        }
    }

    /* Check for Transfer-Encoding header & Smuggling detection (CL.TE / TE.CL) */
    {
        const char *te = case_insensitive_strstr(header_start, "Transfer-Encoding:");
        if (te) {
            const char *cl = case_insensitive_strstr(header_start, "Content-Length:");
            if (cl) {
                return -3; /* Conflicting Transfer-Encoding & Content-Length: Smuggling rejected */
            }
            return -4; /* Chunked Transfer-Encoding rejected to prevent blind body bypass */
        }
    }

    /* Extract Content-Type */
    {
        const char *ct = case_insensitive_strstr(header_start, "Content-Type:");
        if (ct) {
            ct += 13;
            while (*ct == ' ') ct++;
            int i = 0;
            while (*ct && *ct != '\r' && *ct != '\n' && i < (int)sizeof(req->content_type) - 1)
                req->content_type[i++] = *ct++;
            req->content_type[i] = '\0';
        }
    }

    /* Extract Content-Length & detect duplicate/conflicting values (Smuggling check) */
    {
        const char *cl = case_insensitive_strstr(header_start, "Content-Length:");
        if (cl) {
            cl += 15;
            while (*cl == ' ') cl++;
            req->content_length = atoi(cl);

            /* Check for a second Content-Length header */
            const char *cl2 = case_insensitive_strstr(cl, "Content-Length:");
            if (cl2) {
                cl2 += 15;
                while (*cl2 == ' ') cl2++;
                int cl2_val = atoi(cl2);
                if (cl2_val != req->content_length) {
                    req->duplicate_content_length = 1;
                    return -3; /* Conflicting Content-Length rejected */
                }
            }
        }
    }

    /* Extract User-Agent */
    {
        const char *ua = case_insensitive_strstr(header_start, "User-Agent:");
        if (ua) {
            ua += 11;
            while (*ua == ' ') ua++;
            int i = 0;
            while (*ua && *ua != '\r' && *ua != '\n' && i < (int)sizeof(req->user_agent) - 1)
                req->user_agent[i++] = *ua++;
            req->user_agent[i] = '\0';
        }
    }

    /* Extract Referer */
    {
        const char *ref = case_insensitive_strstr(header_start, "Referer:");
        if (ref) {
            ref += 8;
            while (*ref == ' ') ref++;
            int i = 0;
            while (*ref && *ref != '\r' && *ref != '\n' && i < (int)sizeof(req->referer) - 1)
                req->referer[i++] = *ref++;
            req->referer[i] = '\0';
        }
    }

    /* Extract Cookie */
    {
        const char *ck = case_insensitive_strstr(header_start, "Cookie:");
        if (ck) {
            ck += 7;
            while (*ck == ' ') ck++;
            int i = 0;
            while (*ck && *ck != '\r' && *ck != '\n' && i < (int)sizeof(req->cookie) - 1)
                req->cookie[i++] = *ck++;
            req->cookie[i] = '\0';
        }
    }

    /* Extract Body */
    if (body_start && (body_start - raw) < raw_len) {
        int b_len = raw_len - (int)(body_start - raw);
        if (b_len > 0) {
            if (b_len >= (int)sizeof(req->body))
                b_len = (int)sizeof(req->body) - 1;
            memcpy(req->body, body_start, b_len);
            req->body[b_len] = '\0';
            req->body_len = b_len;
        }
    }

    return 0;
}

/* ============================================================
 *  SECURITY RULE ENGINES
 * ============================================================
 */

/* SQL Injection Detection */
static const char *check_sql_injection(const char *input)
{
    static const struct {
        const char *pattern;
        const char *name;
    } sql_patterns[] = {
        { "union select",   "UNION SELECT"   },
        { "union all",      "UNION ALL"      },
        { "' or '1'='1",    "OR 1=1"         },
        { "' or 1=1",       "OR 1=1"         },
        { "\" or 1=1",      "OR 1=1"         },
        { "or 1=1--",       "OR 1=1--"       },
        { "or 1=1",         "OR 1=1"         },
        { "1'='1",          "1'='1"          },
        { "'; drop table",  "DROP TABLE"     },
        { "drop table",     "DROP TABLE"     },
        { "drop database",  "DROP DATABASE"  },
        { "'; --",          "SQL Comment"    },
        { "1'; --",         "SQL Comment"    },
        { "; delete",       "; DELETE"       },
        { "; insert",       "; INSERT"       },
        { "; update",       "; UPDATE"       },
        { "select * from",  "SELECT FROM"    },
        { "insert into",    "INSERT INTO"    },
        { "delete from",    "DELETE FROM"    },
        { "update set",     "UPDATE SET"     },
        { "having 1=1",     "HAVING 1=1"     },
        { "order by",       "ORDER BY"       },
        { "benchmark(",     "BENCHMARK"      },
        { "sleep(",         "SLEEP()"        },
        { "waitfor delay",  "WAITFOR DELAY"  },
        { "load_file(",     "LOAD_FILE"      },
        { "into outfile",   "INTO OUTFILE"   },
        { "into dumpfile",  "INTO DUMPFILE"  },
        { NULL, NULL }
    };

    int i;
    if (!input || input[0] == '\0') return NULL;

    /* 1. Direct check */
    for (i = 0; sql_patterns[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, sql_patterns[i].pattern)) {
            return sql_patterns[i].name;
        }
    }

    /* 2. Check with SQL comments stripped (defeats UN/ * * /ION comment evasions) */
    if (strstr(input, "/*")) {
        char stripped_space[4096];
        char stripped_empty[4096];
        strip_sql_comments(stripped_space, input, sizeof(stripped_space), 1);
        strip_sql_comments(stripped_empty, input, sizeof(stripped_empty), 0);
        for (i = 0; sql_patterns[i].pattern != NULL; i++) {
            if (case_insensitive_strstr(stripped_space, sql_patterns[i].pattern) ||
                case_insensitive_strstr(stripped_empty, sql_patterns[i].pattern)) {
                return sql_patterns[i].name;
            }
        }
        /* Flag suspicious standalone SQL inline comment injection */
        if (case_insensitive_strstr(input, "/**/") &&
            (case_insensitive_strstr(input, "select") || case_insensitive_strstr(input, "union"))) {
            return "SQL Comment Obfuscation";
        }
    }

    return NULL;
}

/* XSS Detection */
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
    if (!input || input[0] == '\0') return NULL;

    for (i = 0; xss_patterns[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, xss_patterns[i].pattern)) {
            return xss_patterns[i].name;
        }
    }

    return NULL;
}

/* Path Traversal Detection */
static const char *check_path_traversal(const char *input, int is_uri_path)
{
    static const struct {
        const char *pattern;
        const char *name;
    } sensitive_files[] = {
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
    if (!input || input[0] == '\0') return NULL;

    /* Always block sensitive system files anywhere */
    for (i = 0; sensitive_files[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, sensitive_files[i].pattern)) {
            return sensitive_files[i].name;
        }
    }

    /* Windows backslash traversal */
    if (strstr(input, "..\\")) return "..\\";

    /* Multiple levels of directory climbing */
    if (strstr(input, "../../")) return "../../";

    /* In the URI path itself (before ?), ANY ../ is a traversal attempt */
    if (is_uri_path && strstr(input, "../")) {
        return "../";
    }

    return NULL;
}

/* Command Injection Detection */
static const char *check_command_injection(const char *input)
{
    static const struct {
        const char *pattern;
        const char *name;
    } cmd_patterns[] = {
        { ";cat ",          ";cat"            },
        { ";cat/",          ";cat/"           },
        { ";ls ",           ";ls"             },
        { ";ls/",           ";ls/"            },
        { "|cat ",          "|cat"            },
        { "|cat/",          "|cat/"           },
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
        { ";nc ",           ";nc"             },
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
    if (!input || input[0] == '\0') return NULL;

    for (i = 0; cmd_patterns[i].pattern != NULL; i++) {
        if (case_insensitive_strstr(input, cmd_patterns[i].pattern)) {
            return cmd_patterns[i].name;
        }
    }

    return NULL;
}

/* ============================================================
 *  COMBINED MULTI-SURFACE SECURITY CHECK
 * ============================================================
 */
static const char *inspect_string(const char *str, const char *surface_name, int is_uri_path)
{
    static char result[256];
    char decoded1[MAX_PATH_LEN];
    char decoded2[MAX_PATH_LEN];
    const char *match;

    if (!str || str[0] == '\0') return NULL;

    /* Decode once and twice to defeat URL percent-encoding & double-encoding */
    url_decode(decoded1, str, sizeof(decoded1));
    url_decode(decoded2, decoded1, sizeof(decoded2));

    const char *variants[] = { str, decoded1, decoded2 };
    int v;

    for (v = 0; v < 3; v++) {
        match = check_sql_injection(variants[v]);
        if (match) {
            snprintf(result, sizeof(result), "SQL Injection: %s [in %s]", match, surface_name);
            return result;
        }

        match = check_xss(variants[v]);
        if (match) {
            snprintf(result, sizeof(result), "XSS: %s [in %s]", match, surface_name);
            return result;
        }

        match = check_path_traversal(variants[v], is_uri_path);
        if (match) {
            snprintf(result, sizeof(result), "Path Traversal: %s [in %s]", match, surface_name);
            return result;
        }

        match = check_command_injection(variants[v]);
        if (match) {
            snprintf(result, sizeof(result), "Command Injection: %s [in %s]", match, surface_name);
            return result;
        }
    }

    return NULL;
}

static const char *run_security_checks(const struct http_request *req)
{
    const char *threat;
    char uri_path[MAX_PATH_LEN];
    const char *query_string = NULL;

    /* Split path into uri_path (before ?) and query_string (after ?) */
    strncpy(uri_path, req->path, sizeof(uri_path) - 1);
    uri_path[sizeof(uri_path) - 1] = '\0';
    char *qmark = strchr(uri_path, '?');
    if (qmark) {
        *qmark = '\0';
        query_string = req->path + (qmark - uri_path) + 1;
    }

    /* 1. Inspect URI path (strict traversal checking) */
    threat = inspect_string(uri_path, "URI Path", 1);
    if (threat) return threat;

    /* 2. Inspect Query string (if present) */
    if (query_string && query_string[0] != '\0') {
        threat = inspect_string(query_string, "Query String", 0);
        if (threat) return threat;
    }

    /* 3. Inspect Body (POST/PUT payload) */
    if (req->body_len > 0) {
        threat = inspect_string(req->body, "Body", 0);
        if (threat) return threat;
    }

    /* 4. Inspect Headers: Host, User-Agent, Referer, Cookie */
    if (req->host[0] != '\0') {
        threat = inspect_string(req->host, "Host Header", 0);
        if (threat) return threat;
    }

    if (req->user_agent[0] != '\0') {
        threat = inspect_string(req->user_agent, "User-Agent Header", 0);
        if (threat) return threat;
    }

    if (req->referer[0] != '\0') {
        threat = inspect_string(req->referer, "Referer Header", 0);
        if (threat) return threat;
    }

    if (req->cookie[0] != '\0') {
        threat = inspect_string(req->cookie, "Cookie Header", 0);
        if (threat) return threat;
    }

    return NULL;
}

/* ============================================================
 *  RATE LIMITER
 * ============================================================
 */
static int check_rate_limit(const char *client_ip)
{
    time_t now = time(NULL);
    int i;

    for (i = 0; i < ip_count; i++) {
        if (strcmp(ip_table[i].ip, client_ip) == 0) {
            if (now - ip_table[i].window_start >= RATE_WINDOW) {
                ip_table[i].window_start = now;
                ip_table[i].request_count = 1;
                return 0;
            }

            ip_table[i].request_count++;
            if (ip_table[i].request_count > MAX_REQUESTS) {
                return 1;
            }
            return 0;
        }
    }

    if (ip_count < MAX_TRACKED_IPS) {
        i = ip_count++;
    } else {
        int oldest_idx = 0;
        time_t oldest_time = ip_table[0].window_start;
        for (i = 1; i < MAX_TRACKED_IPS; i++) {
            if (ip_table[i].window_start < oldest_time) {
                oldest_time = ip_table[i].window_start;
                oldest_idx = i;
            }
        }
        i = oldest_idx;
    }

    strncpy(ip_table[i].ip, client_ip, INET_ADDRSTRLEN - 1);
    ip_table[i].ip[INET_ADDRSTRLEN - 1] = '\0';
    ip_table[i].request_count = 1;
    ip_table[i].window_start  = now;

    return 0;
}

/* ============================================================
 *  REQUEST LOGGING
 * ============================================================
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

    now = time(NULL);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    if (reason && reason[0] != '\0') {
        printf("  [%s] %s %s %s %s (%s)\n",
               timestamp, client_ip, method, path, verdict, reason);
    } else {
        printf("  [%s] %s %s %s %s\n",
               timestamp, client_ip, method, path, verdict);
    }

    if (!log_fp) {
        log_fp = fopen(LOG_FILE, "a");
    }

    if (log_fp) {
        if (reason && reason[0] != '\0') {
            fprintf(log_fp, "[%s] %s %s %s %s (%s)\n",
                    timestamp, client_ip, method, path, verdict, reason);
        } else {
            fprintf(log_fp, "[%s] %s %s %s %s\n",
                    timestamp, client_ip, method, path, verdict);
        }
        fflush(log_fp);
    }
}

static void print_stats_if_needed(void)
{
    if (stats.total_requests > 0 && stats.total_requests % STATS_INTERVAL == 0) {
        printf("\n  ┌──── WAF Stats (after %lu requests) ────┐\n", stats.total_requests);
        printf("  │  Allowed      : %-10lu              │\n", stats.allowed_requests);
        printf("  │  Blocked      : %-10lu              │\n", stats.blocked_requests);
        printf("  │  Rate-Limited : %-10lu              │\n", stats.rate_limited_requests);
        printf("  └─────────────────────────────────────────┘\n\n");
    }
}

/* ============================================================
 *  ERROR RESPONSE PAGES
 * ============================================================
 */
static void send_403_blocked(int client_fd, const char *rule_name)
{
    char body[2048];
    char response[4096];
    int body_len;

    body_len = snprintf(body, sizeof(body),
        "<!DOCTYPE html>\n<html>\n<head><title>403 - Blocked by WAF</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fef2f2;\">\n"
        "  <h1 style=\"color: #dc2626;\">&#x1F6E1; 403 - Blocked by WAF</h1>\n"
        "  <p style=\"color: #991b1b; font-size: 18px;\">Your request was blocked by the Web Application Firewall.</p>\n"
        "  <div style=\"background: #fee2e2; border: 1px solid #fca5a5; border-radius: 8px; padding: 15px; display: inline-block;\">\n"
        "    <strong>Rule triggered:</strong> %s\n"
        "  </div>\n"
        "</body>\n</html>\n",
        rule_name ? rule_name : "Unknown");

    snprintf(response, sizeof(response),
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        body_len, body);

    send(client_fd, response, strlen(response), 0);
}

static void send_400_bad_request(int client_fd, const char *reason)
{
    char body[1024];
    char response[2048];
    int body_len;

    body_len = snprintf(body, sizeof(body),
        "<!DOCTYPE html>\n<html>\n<head><title>400 - Bad Request</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; padding: 50px;\">\n"
        "  <h1>400 - Bad Request</h1>\n"
        "  <p>%s</p>\n"
        "</body>\n</html>\n",
        reason ? reason : "Malformed HTTP request");

    snprintf(response, sizeof(response),
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        body_len, body);

    send(client_fd, response, strlen(response), 0);
}

static void send_414_uri_too_long(int client_fd)
{
    const char *body =
        "<!DOCTYPE html>\n<html>\n<head><title>414 - URI Too Long</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; padding: 50px;\">\n"
        "  <h1>414 - URI Too Long</h1>\n"
        "  <p>The requested URL exceeds the maximum allowed length.</p>\n"
        "</body>\n</html>\n";

    char response[1024];
    snprintf(response, sizeof(response),
        "HTTP/1.1 414 URI Too Long\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        (int)strlen(body), body);

    send(client_fd, response, strlen(response), 0);
}

static void send_429_rate_limited(int client_fd)
{
    const char *body =
        "<!DOCTYPE html>\n<html>\n<head><title>429 - Too Many Requests</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fffbeb;\">\n"
        "  <h1 style=\"color: #d97706;\">&#x23F3; 429 - Too Many Requests</h1>\n"
        "  <p style=\"color: #92400e;\">You are sending requests too quickly. Please slow down.</p>\n"
        "</body>\n</html>\n";

    char response[1024];
    snprintf(response, sizeof(response),
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Retry-After: %d\r\n"
        "Connection: close\r\n\r\n%s",
        (int)strlen(body), RATE_WINDOW, body);

    send(client_fd, response, strlen(response), 0);
}

static void send_502_bad_gateway(int client_fd)
{
    const char *body =
        "<!DOCTYPE html>\n<html>\n<head><title>502 - Bad Gateway</title></head>\n"
        "<body style=\"font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f3f4f6;\">\n"
        "  <h1>502 - Bad Gateway</h1>\n"
        "  <p>The backend server is not responding.</p>\n"
        "</body>\n</html>\n";

    char response[1024];
    snprintf(response, sizeof(response),
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        (int)strlen(body), body);

    send(client_fd, response, strlen(response), 0);
}

/* ============================================================
 *  BACKEND FORWARDING
 * ============================================================
 */
static int forward_to_backend(int client_fd, const struct http_request *req)
{
    int backend_fd;
    struct sockaddr_in backend_addr;
    char buffer[8192];
    ssize_t bytes;

    backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_fd < 0) return -1;

    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port   = htons(BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_IP, &backend_addr.sin_addr);

    if (connect(backend_fd, (struct sockaddr *)&backend_addr, sizeof(backend_addr)) < 0) {
        close(backend_fd);
        return -1;
    }

    if (send(backend_fd, req->full_request, req->full_request_len, 0) < 0) {
        close(backend_fd);
        return -1;
    }

    while ((bytes = recv(backend_fd, buffer, sizeof(buffer), 0)) > 0) {
        if (send(client_fd, buffer, bytes, 0) < 0) break;
    }

    close(backend_fd);
    return 0;
}

/* ============================================================
 *  REQUEST HANDLER (Multi-Read TCP Stream Buffering)
 * ============================================================
 */
static void handle_client(int client_fd, const char *client_ip)
{
    static char buffer[BUFFER_SIZE];
    int total_received = 0;
    int expected_content_len = -1;
    const char *threat;
    int parse_res;

    /* Track total request start time for overall deadline (Slowloris defense) */
    struct timespec start_ts, now_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    /* --- Multi-read loop: buffer entire headers + body --- */
    while (total_received < BUFFER_SIZE - 1) {
        /* Enforce absolute per-request deadline across all reads */
        clock_gettime(CLOCK_MONOTONIC, &now_ts);
        double elapsed = (double)(now_ts.tv_sec - start_ts.tv_sec) +
                         (double)(now_ts.tv_nsec - start_ts.tv_nsec) / 1e9;
        double remaining = TOTAL_REQUEST_DEADLINE - elapsed;
        if (remaining <= 0.05) {
            /* Total per-request deadline expired: Slowloris drip-feed neutralized */
            break;
        }

        /* Dynamically update SO_RCVTIMEO to remaining budget */
        struct timeval tv;
        tv.tv_sec = (time_t)remaining;
        tv.tv_usec = (suseconds_t)((remaining - tv.tv_sec) * 1000000.0);
        if (tv.tv_sec == 0 && tv.tv_usec < 10000) tv.tv_usec = 10000;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int n = recv(client_fd, buffer + total_received, BUFFER_SIZE - 1 - total_received, 0);
        if (n <= 0) break;
        total_received += n;
        buffer[total_received] = '\0';

        /* Check if headers are complete */
        const char *hdr_end = strstr(buffer, "\r\n\r\n");
        if (!hdr_end) hdr_end = strstr(buffer, "\n\n");

        if (hdr_end) {
            /* If we haven't checked Content-Length yet, check it now */
            if (expected_content_len < 0) {
                const char *cl = case_insensitive_strstr(buffer, "Content-Length:");
                if (cl) {
                    expected_content_len = atoi(cl + 15);
                } else {
                    expected_content_len = 0;
                }
            }

            int header_bytes = (int)(hdr_end - buffer) + ((hdr_end[0] == '\r') ? 4 : 2);
            int body_bytes = total_received - header_bytes;

            /* If we have received all advertised body bytes, we are done */
            if (body_bytes >= expected_content_len) {
                break;
            }
        }
    }

    if (total_received <= 0) {
        close(client_fd);
        return;
    }

    /* --- Parse the buffered HTTP request --- */
    parse_res = parse_http_request(buffer, total_received, &g_req);

    if (parse_res == -2) {
        /* 414 URI Too Long */
        log_request(client_ip, "GET", "/...", "BLOCKED", "URI Too Long (> 4096 bytes)");
        send_414_uri_too_long(client_fd);
        stats.blocked_requests++;
        stats.total_requests++;
        close(client_fd);
        return;
    }

    if (parse_res == -3) {
        /* 400 Bad Request: Conflicting Content-Length or CL.TE / TE.CL Smuggling */
        log_request(client_ip, "POST", "/", "BLOCKED", "Conflicting headers (Request Smuggling guard)");
        send_400_bad_request(client_fd, "Conflicting Content-Length or Transfer-Encoding headers detected");
        stats.blocked_requests++;
        stats.total_requests++;
        close(client_fd);
        return;
    }

    if (parse_res == -4) {
        /* 400 Bad Request: Transfer-Encoding chunked unsupported */
        log_request(client_ip, "POST", "/", "BLOCKED", "Chunked Transfer-Encoding rejected (Bypass guard)");
        send_400_bad_request(client_fd, "Transfer-Encoding: chunked not supported for inspection");
        stats.blocked_requests++;
        stats.total_requests++;
        close(client_fd);
        return;
    }

    if (parse_res < 0) {
        /* 400 Bad Request: Malformed */
        send_400_bad_request(client_fd, "Malformed HTTP request");
        close(client_fd);
        return;
    }

    stats.total_requests++;
    printf("\n  [REQUEST #%lu] %s %s from %s\n",
           stats.total_requests, g_req.method, g_req.path, client_ip);

    /* --- Rate Limiting --- */
    if (check_rate_limit(client_ip)) {
        printf("  [RATE-LIMITED] %s exceeded %d req in %ds\n",
               client_ip, MAX_REQUESTS, RATE_WINDOW);
        log_request(client_ip, g_req.method, g_req.path, "RATE-LIMITED", NULL);
        send_429_rate_limited(client_fd);
        stats.rate_limited_requests++;
        print_stats_if_needed();
        close(client_fd);
        return;
    }

    /* --- Security Rules Inspection --- */
    threat = run_security_checks(&g_req);
    if (threat) {
        printf("  [BLOCKED] Threat detected: %s\n", threat);
        log_request(client_ip, g_req.method, g_req.path, "BLOCKED", threat);
        send_403_blocked(client_fd, threat);
        stats.blocked_requests++;
        print_stats_if_needed();
        close(client_fd);
        return;
    }

    /* --- Forwarding to Backend --- */
    printf("  [ALLOWED] Forwarding to backend %s:%d\n", BACKEND_IP, BACKEND_PORT);
    if (forward_to_backend(client_fd, &g_req) < 0) {
        log_request(client_ip, g_req.method, g_req.path, "ALLOWED", "backend unreachable (502)");
        send_502_bad_gateway(client_fd);
    } else {
        log_request(client_ip, g_req.method, g_req.path, "ALLOWED", NULL);
    }

    stats.allowed_requests++;
    print_stats_if_needed();
    close(client_fd);
}

/* ============================================================
 *  MAIN & ACCEPT LOOP
 * ============================================================
 */
int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char client_ip[INET_ADDRSTRLEN];
    int opt = 1;

    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        fprintf(stderr, "  [WARNING] Could not open %s for writing: %s\n",
                LOG_FILE, strerror(errno));
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("  [FATAL] Socket creation failed");
        if (log_fp) fclose(log_fp);
        return 1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(WAF_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("  [FATAL] Bind failed");
        close(server_fd);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("  [FATAL] Listen failed");
        close(server_fd);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    printf("\n");
    printf("  ============================================\n");
    printf("         WAF - Web Application Firewall       \n");
    printf("  ============================================\n");
    printf("    Listening on    : port %d\n", WAF_PORT);
    printf("    Backend server  : %s:%d\n", BACKEND_IP, BACKEND_PORT);
    printf("    Rate limit      : %d req/%ds per IP\n", MAX_REQUESTS, RATE_WINDOW);
    printf("    Log file        : %s\n", LOG_FILE);
    printf("    Rules active    : SQLi, XSS, Path Traversal, Command Injection\n");
    printf("    Evasion guards  : URL Decoding, Double-Decode, Comment Stripping\n");
    printf("  ============================================\n\n");
    printf("  Waiting for connections...\n");

    while (1) {
        client_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            continue;
        }

        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        handle_client(client_fd, client_ip);
    }

    close(server_fd);
    if (log_fp) fclose(log_fp);
    return 0;
}
