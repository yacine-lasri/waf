/*
 * step03_http_parser.c — HTTP Request Parser + Proxy with Logging
 *
 * Evolution from Step 02: instead of forwarding raw bytes blindly,
 * we now PARSE the HTTP request first. This lets us:
 *   - Log exactly what method, path, and headers were sent
 *   - Inspect specific fields (this is how the WAF will work)
 *
 * The parser splits a raw HTTP request string into:
 *   - method  (GET, POST, etc.)
 *   - path    (/index.html, /api/users, etc.)
 *   - headers (Host, User-Agent, etc.)
 *   - body    (POST form data, JSON, etc.)
 *
 * Parsing strategy (using \r\n as you identified):
 *   1. First \r\n ends the request line → split by space for method + path
 *   2. Each subsequent \r\n separates a header line
 *   3. \r\n\r\n (blank line) = end of headers
 *   4. Everything after = body
 *
 * Compile:  gcc step03_http_parser.c -o step03_http_parser
 * Run:      ./step03_http_parser
 *           (make sure step02_backend is already running!)
 * Test:     curl http://localhost:8080
 *           curl http://localhost:8080/api/data
 *           curl -X POST -d "user=admin&pass=secret" http://localhost:8080/login
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WAF_PORT     8080
#define BACKEND_PORT 8888
#define BACKEND_IP   "127.0.0.1"
#define BUFFER_SIZE  8192

/* ============================================================
 * THE HTTP REQUEST STRUCT
 *
 * This holds a parsed HTTP request in organized fields.
 * Before parsing, the request is just a big string like:
 *   "GET /page HTTP/1.1\r\nHost: localhost\r\n\r\n"
 *
 * After parsing, we have:
 *   method  = "GET"
 *   path    = "/page"
 *   version = "HTTP/1.1"
 *   headers = "Host: localhost\r\n"
 *   body    = ""
 *
 * This makes it easy to inspect individual parts.
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
 * parse_http_request() — The parser function
 *
 * Takes: raw request string + pointer to a struct to fill
 * Returns: 0 on success, -1 if the request is malformed
 *
 * This is string manipulation in C — we use strstr() to find
 * substrings and strncpy() to copy pieces out.
 *
 * strstr(haystack, needle) — finds "needle" inside "haystack"
 *   Returns a pointer to where it found it, or NULL if not found.
 *   This is how we find each \r\n.
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
 *
 * This is for learning/debugging. In a real WAF you'd log
 * this to a file, but for now let's see it on screen.
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

/* forward_to_backend() — same as Step 02, no changes */
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

    printf("=== WAF Proxy (with HTTP parsing) ===\n");
    printf("Listening on port %d, forwarding to %s:%d\n\n",
           WAF_PORT, BACKEND_IP, BACKEND_PORT);

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

        /*
         * NEW: Parse the HTTP request before forwarding.
         *
         * Before Step 03: we just saw a blob of text.
         * Now: we know the method, path, headers, and body separately.
         */
        struct http_request parsed;
        if (parse_http_request(request, &parsed) == 0) {
            printf("[WAF] %s %s\n", parsed.method, parsed.path);
            print_parsed_request(&parsed);

            /* ============================================
             * WAF INSPECTION POINT
             *
             * Now that we have parsed fields, we CAN check:
             *   parsed.path — for path traversal (../../)
             *   parsed.body — for SQL injection (' OR 1=1)
             *   parsed.method — block unwanted methods
             *
             * Next step: we'll add these checks!
             * ============================================ */

        } else {
            printf("[WAF] Malformed request, dropping.\n");
            close(client_fd);
            continue;
        }

        /* Forward to backend and relay response (same as Step 02) */
        char response[BUFFER_SIZE];
        int resp_len = forward_to_backend(request, req_len,
                                          response, BUFFER_SIZE);

        if (resp_len > 0) {
            send(client_fd, response, resp_len, 0);
            printf("[WAF] <-- forwarded %d bytes back to client\n\n", resp_len);
        } else {
            const char *err_body = "<h1>502 Bad Gateway</h1>";
            char err_resp[512];
            int err_len = snprintf(err_resp, 512,
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "\r\n%s",
                (int)strlen(err_body), err_body);
            send(client_fd, err_resp, err_len, 0);
            printf("[WAF] <-- 502 (backend down)\n\n");
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
