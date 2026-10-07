/*
 * step02_proxy.c — TCP Proxy (the skeleton of our WAF)
 *
 * This program is BOTH a server and a client:
 *   - SERVER on port 8080: accepts connections from browsers/clients
 *   - CLIENT to port 8888: forwards requests to the backend
 *
 * Traffic flow:
 *   Client:??? --> Proxy:8080 --> Backend:8888
 *   Client:??? <-- Proxy:8080 <-- Backend:8888
 *
 * Right now it forwards EVERYTHING blindly.
 * In the next steps, we'll inspect the traffic and block attacks.
 * That's what turns a "proxy" into a "firewall."
 *
 * Compile:  gcc step02_proxy.c -o step02_proxy
 * Run:      ./step02_proxy
 *           (make sure step02_backend is already running!)
 * Test:     curl http://localhost:8080
 *
 * New concepts vs Step 01:
 *   - connect()  — the client-side function to reach the backend
 *   - send()     — sending data (we only used recv before)
 *   - The server loop (while(1) with accept)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>      /* inet_addr — to convert IP string to binary */

#define WAF_PORT     8080
#define BACKEND_PORT 8888
#define BACKEND_IP   "127.0.0.1"
#define BUFFER_SIZE  4096

/*
 * forward_to_backend() — The CLIENT side of our proxy
 *
 * This function takes the raw data from the client,
 * opens a NEW connection to the backend, sends the data,
 * receives the response, and returns it.
 *
 * This is where connect() lives — the one new function.
 *
 * Parameters:
 *   client_data     — the raw bytes the client sent us
 *   data_len        — how many bytes
 *   response_buf    — buffer to store the backend's response
 *   response_bufsize — size of that buffer
 *
 * Returns: number of bytes in the response, or -1 on error
 */
int forward_to_backend(const char *client_data, int data_len,
                       char *response_buf, int response_bufsize)
{
    /*
     * Create a NEW socket for talking to the backend.
     * Every request gets its own connection.
     * Same socket() call as before — nothing new here.
     */
    int backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_fd == -1) {
        perror("socket to backend");
        return -1;
    }

    /*
     * Set up the backend's address.
     * Same struct sockaddr_in, but this time we fill in
     * the BACKEND's IP and port (not our own).
     *
     * inet_addr() converts "127.0.0.1" (a string) into
     * the binary format that sin_addr.s_addr expects.
     * Beej covers this in Ch 3.4 — inet_pton() is the
     * newer version, but inet_addr works fine for IPv4.
     */
    struct sockaddr_in backend_addr;
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(BACKEND_PORT);
    backend_addr.sin_addr.s_addr = inet_addr(BACKEND_IP);

    /*
     * connect() — THE NEW FUNCTION
     *
     * This is the client-side equivalent of accept().
     * It initiates the TCP three-way handshake:
     *   Our proxy sends SYN     --> backend
     *   Backend sends SYN-ACK   --> proxy
     *   Our proxy sends ACK     --> backend
     *
     * After connect() returns, we have a live connection
     * to the backend and can send/recv on backend_fd.
     *
     * If the backend isn't running, connect() returns -1
     * and sets errno to ECONNREFUSED ("Connection refused").
     */
    if (connect(backend_fd, (struct sockaddr *)&backend_addr,
                sizeof(backend_addr)) == -1) {
        perror("connect to backend");
        close(backend_fd);
        return -1;
    }

    /*
     * send() — Send the client's request to the backend.
     *
     * send() is the counterpart to recv().
     *   recv() = read data FROM a socket
     *   send() = write data TO a socket
     *
     * It returns the number of bytes actually sent.
     * Important: it might not send ALL your data in one call
     * (Beej Ch 7.4). For now, our requests are small enough
     * that one send() is fine. We'll handle partial sends later.
     */
    send(backend_fd, client_data, data_len, 0);

    /*
     * recv() — Read the backend's response.
     *
     * The backend sends an HTTP response. We read it into
     * response_buf so we can later send it back to the client.
     */
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
    /* Same server setup as Step 01 — nothing new here */
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

    printf("=== WAF Proxy ===\n");
    printf("Listening on port %d, forwarding to %s:%d\n\n",
           WAF_PORT, BACKEND_IP, BACKEND_PORT);

    /* The server loop — handle connections forever */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        /* Block until a client connects */
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
                               &client_len);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }

        /* Receive the client's request */
        char request[BUFFER_SIZE];
        int req_len = recv(client_fd, request, BUFFER_SIZE - 1, 0);

        if (req_len <= 0) {
            close(client_fd);
            continue;
        }
        request[req_len] = '\0';

        /* Log the first line of the request */
        char first_line[256];
        int i = 0;
        while (i < req_len && i < 255 && request[i] != '\r'
               && request[i] != '\n') {
            first_line[i] = request[i];
            i++;
        }
        first_line[i] = '\0';
        printf("[PROXY] --> %s\n", first_line);

        /* ============================================
         * THIS IS WHERE THE WAF INSPECTION WILL GO.
         *
         * Right now: forward everything.
         * Later: check for SQL injection, XSS, etc.
         * If attack detected: send a "403 Forbidden"
         * response and DON'T forward to backend.
         * ============================================ */

        /* Forward to the backend and get the response */
        char response[BUFFER_SIZE];
        int resp_len = forward_to_backend(request, req_len,
                                          response, BUFFER_SIZE);

        if (resp_len > 0) {
            /* Send the backend's response back to the client */
            send(client_fd, response, resp_len, 0);

            /* Log the response status */
            char status_line[64];
            int j = 0;
            while (j < resp_len && j < 63 && response[j] != '\r'
                   && response[j] != '\n') {
                status_line[j] = response[j];
                j++;
            }
            status_line[j] = '\0';
            printf("[PROXY] <-- %s\n\n", status_line);
        } else {
            /* Backend is down — send an error to the client */
            const char *err_body = "<h1>502 Bad Gateway</h1>"
                                   "<p>Backend is not available.</p>";
            char err_resp[512];
            int err_len = snprintf(err_resp, 512,
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "\r\n"
                "%s",
                (int)strlen(err_body), err_body);
            send(client_fd, err_resp, err_len, 0);
            printf("[PROXY] <-- 502 Bad Gateway (backend down)\n\n");
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
