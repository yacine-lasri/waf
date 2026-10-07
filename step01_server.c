/*
 * step01_server.c — Our first TCP server
 *
 * What this does:
 *   1. Listens on port 8080
 *   2. Waits for ONE client to connect
 *   3. Reads what they send
 *   4. Prints it out
 *   5. Quits
 *
 * Compile:  gcc step01_server.c -o step01_server
 * Run:      ./step01_server
 * Test:     (in another terminal) echo "hello" | nc localhost 8080
 *
 * This follows Beej's Guide Chapter 5 flow:
 *   socket() -> bind() -> listen() -> accept() -> recv() -> close()
 */

#include <stdio.h>          /* printf, perror */
#include <stdlib.h>         /* exit */
#include <string.h>         /* memset */
#include <unistd.h>         /* close */
#include <sys/socket.h>     /* socket, bind, listen, accept, recv */
#include <netinet/in.h>     /* struct sockaddr_in, INADDR_ANY */

#define PORT 8080
#define BUFFER_SIZE 1024

int main(void)
{
    /*
     * STEP 1: Create the socket
     *
     * socket() takes 3 arguments:
     *   AF_INET     — We want IPv4
     *   SOCK_STREAM — We want TCP (reliable, ordered data)
     *   0           — Let the OS pick the protocol (it picks TCP for SOCK_STREAM)
     *
     * It returns a file descriptor (just an int).
     * On failure, it returns -1.
     */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    printf("[1] Socket created (fd=%d)\n", server_fd);

    /*
     * STEP 2: Set socket options — SO_REUSEADDR
     *
     * If we stop our server and restart it quickly, the OS might say
     * "that port is still in use" for about 60 seconds. SO_REUSEADDR
     * tells the OS: "I know, let me reuse it anyway."
     *
     * Without this, you'd get "Address already in use" errors
     * every time you restart during development.
     */
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[2] Socket option SO_REUSEADDR set\n");

    /*
     * STEP 3: Set up the address struct
     *
     * struct sockaddr_in holds:
     *   sin_family  — Address family (AF_INET for IPv4)
     *   sin_port    — Port number IN NETWORK BYTE ORDER (big-endian)
     *   sin_addr    — IP address to bind to
     *
     * INADDR_ANY means "listen on ALL network interfaces."
     * If your machine has WiFi (192.168.1.5) and Ethernet (10.0.0.2),
     * INADDR_ANY listens on both. For our WAF, we want to catch
     * everything coming in.
     *
     * htons() = Host TO Network Short — converts our port number
     * from little-endian (Intel x86) to big-endian (network standard).
     */
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));     /* zero out the struct first */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    /*
     * STEP 4: Bind the socket to our address
     *
     * bind() associates our socket with the IP + port we just set up.
     * After this call, the OS knows: "traffic arriving on port 8080
     * belongs to this program."
     *
     * Note the (struct sockaddr *) cast — Beej explains in Ch 3.3:
     * bind() takes a generic sockaddr pointer. We're using the
     * IPv4-specific sockaddr_in, so we have to cast it. This is
     * how C handles "one function that works with different address types."
     */
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[3] Bound to port %d\n", PORT);

    /*
     * STEP 5: Start listening
     *
     * The second argument (5) is the backlog — how many connections
     * can wait in the OS queue before we accept() them.
     * For our simple test, 5 is plenty.
     */
    if (listen(server_fd, 5) == -1) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[4] Listening on port %d... waiting for a connection\n", PORT);

    /*
     * STEP 6: Accept a connection
     *
     * accept() blocks here — the program pauses and waits.
     * When a client connects, accept() returns a BRAND NEW socket (client_fd).
     * This new socket is our private line with that specific client.
     * server_fd stays untouched — it could keep accepting more clients.
     *
     * We also get the client's address info (their IP and port)
     * filled into client_addr.
     */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd == -1) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[5] Client connected! (new fd=%d)\n", client_fd);

    /*
     * STEP 7: Receive data from the client
     *
     * recv() reads up to BUFFER_SIZE bytes into our buffer.
     * It returns the number of bytes actually received.
     * Returns 0 if the client disconnected.
     * Returns -1 on error.
     *
     * buffer[bytes_received] = '\0' — we null-terminate so we
     * can safely print it as a C string.
     */
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("[6] Received %d bytes:\n", bytes_received);
        printf("--- START ---\n");
        printf("%s", buffer);
        printf("--- END ---\n");
    } else if (bytes_received == 0) {
        printf("[6] Client disconnected without sending anything\n");
    } else {
        perror("recv failed");
    }

    /*
     * STEP 8: Clean up
     *
     * Always close your sockets. The OS will do it when your
     * program exits anyway, but it's good practice — especially
     * later when our WAF runs continuously.
     */
    close(client_fd);
    close(server_fd);
    printf("[7] Sockets closed. Done.\n");

    return 0;
}
