/*
 * step02_backend.c — Simple backend web server
 *
 * This is the "real" web server our WAF will protect.
 * It listens on port 8888 and responds with a basic HTML page.
 *
 * New concept vs Step 01: this server LOOPS.
 * Step 01 handled one connection and quit.
 * A real server goes back to accept() after each client.
 *
 * Compile:  gcc step02_backend.c -o step02_backend
 * Run:      ./step02_backend
 * Test:     curl http://localhost:8888
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8888
#define BUFFER_SIZE 4096

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
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) == -1) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[Backend] Running on port %d\n", PORT);

    /*
     * THE LOOP — this is the difference from Step 01.
     * After handling a client, we go right back to accept()
     * and wait for the next one. The server runs forever
     * until you kill it with Ctrl+C.
     */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == -1) {
            perror("accept");
            continue;   /* don't crash — just try the next connection */
        }

        /* Read the request (we don't parse it yet — just receive it) */
        char buffer[BUFFER_SIZE];
        int n = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';

            /* Grab just the first line for logging (e.g. "GET / HTTP/1.1") */
            char first_line[256];
            int i = 0;
            while (i < n && i < 255 && buffer[i] != '\r' && buffer[i] != '\n') {
                first_line[i] = buffer[i];
                i++;
            }
            first_line[i] = '\0';
            printf("[Backend] %s\n", first_line);
        }

        /* Build an HTTP response */
        const char *body =
            "<html>\n"
            "<body>\n"
            "<h1>Backend Server</h1>\n"
            "<p>This response came from the backend on port 8888.</p>\n"
            "<p>If you're seeing this through port 8080, the proxy works!</p>\n"
            "</body>\n"
            "</html>\n";

        char response[BUFFER_SIZE];
        int body_len = strlen(body);
        int resp_len = snprintf(response, BUFFER_SIZE,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            body_len, body);

        send(client_fd, response, resp_len, 0);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
