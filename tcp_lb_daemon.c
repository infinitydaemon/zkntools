 /* CWD SYSTEMS
 * Walletshield TCP Connection Load Balancer Daemon
 * Uses 1.4KB of RAM per generated thread.
 * Description:
 *   This program acts as a simple TCP connection load balancer. It listens on
 *   port 7070 for incoming TCP connections and distributes them to a set of
 *   backend nodes using a round-robin algorithm. The program runs as a daemon
 *   and logs its activity to a log file.
 *
 * Usage:
 *   Compile the program:
 *    gcc -o tcp_lb_daemon tcp_lb_daemon.c -lpthread
 *
 *   Run the program as a daemon:
 *     sudo ./tcp_lb_daemon
 *
 *   Check the log file for output:
 *     tail -f /var/log/tcp_lb_daemon.log
 *
 * Configuration:
 *   - Backend nodes are defined in the `backend_nodes` array. Modify this array
 *     to include the IP addresses of your backend servers.
 *   - The load balancer listens on port 7070. You can change this by modifying
 *     the `lb_addr.sin_port` value.
 *   - The log file is created at `/var/log/tcp_lb_daemon.log`. You can change
 *     this path by modifying the `LOG_FILE` macro.
 *
 * Features:
 *   - Runs as a daemon process.
 *   - Logs all activity to a log file with timestamps.
 *   - Uses a simple round-robin algorithm to distribute connections.
 *   - Forwards data bidirectionally between clients and backend servers.
 *
 * Limitations:
 *   - Does not include health checks for backend servers.
 *   - Does not support dynamic configuration (backend nodes are hardcoded).
 *   - Does not handle errors or retries for failed backend connections.
 *
 * Example:
 *   If the backend_nodes array contains:
 *     const char *backend_nodes[] = {"192.168.1.101", "192.168.1.102", "192.168.1.103"};
 *
 *   The load balancer will distribute connections as follows:
 *     Connection 1 -> 192.168.1.101
 *     Connection 2 -> 192.168.1.102
 *     Connection 3 -> 192.168.1.103
 *     Connection 4 -> 192.168.1.101
 *     Connection 5 -> 192.168.1.102
 *     ... and so on.
 *
 * Logging:
 *   The program logs the following events:
 *     - When the load balancer starts listening on port 7070.
 *     - When a new client connection is accepted.
 *     - When a connection to a backend server is established.
 *     - When a connection is closed.
 *
 * Notes:
 *   - Ensure you have the necessary permissions to write to the log file
 *     (/var/log/tcp_lb_daemon.log).
 *   - This is a basic implementation and is intended for educational purposes.
 *     For production use, consider using a more robust solution like HAProxy.
 *
 * Author: Professor Raziel K
 * Date: March 19, 2025
 * Version: 1.0 stable
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#define BACKEND_NODES 3
#define BUFFER_SIZE 1024
#define LOG_FILE "/var/log/tcp_lb_daemon.log"

const char *backend_nodes[BACKEND_NODES] = {
    "192.168.1.101",
    "192.168.1.102",
    "192.168.1.103"
};

int current_backend = 0; // Shared variable for round-robin selection
pthread_mutex_t backend_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for thread-safe access

void daemonize() {
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        // Parent process exits
        exit(EXIT_SUCCESS);
    }

    // Create a new session
    if (setsid() < 0) {
        perror("setsid failed");
        exit(EXIT_FAILURE);
    }

    // Change the working directory to root
    chdir("/");

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect stdout and stderr to the log file
    int log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd < 0) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }

    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
    close(log_fd);
}

void log_message(const char *message) {
    time_t now;
    time(&now);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0'; // Remove newline
    printf("[%s] %s\n", timestamp, message);
}

// Thread function to handle client connections
void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    int backend_socket;
    struct sockaddr_in backend_addr;
    char buffer[BUFFER_SIZE];

    // Select the backend server (round-robin)
    pthread_mutex_lock(&backend_mutex);
    const char *backend_ip = backend_nodes[current_backend];
    current_backend = (current_backend + 1) % BACKEND_NODES;
    pthread_mutex_unlock(&backend_mutex);

    // Connect to the backend server
    backend_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_socket == -1) {
        log_message("Backend socket creation failed");
        close(client_socket);
        pthread_exit(NULL);
    }

    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(7070);
    inet_pton(AF_INET, backend_ip, &backend_addr.sin_addr);

    if (connect(backend_socket, (struct sockaddr *)&backend_addr, sizeof(backend_addr)) < 0) {
        log_message("Connection to backend failed");
        close(backend_socket);
        close(client_socket);
        pthread_exit(NULL);
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Connected to backend: %s", backend_ip);
    log_message(log_msg);

    // Forward data between client and backend
    while (1) {
        ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            break;
        }

        send(backend_socket, buffer, bytes_received, 0);

        bytes_received = recv(backend_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            break;
        }

        send(client_socket, buffer, bytes_received, 0);
    }

    // Close the connections
    close(backend_socket);
    close(client_socket);

    log_message("Connection closed");
    pthread_exit(NULL);
}

int main() {
    int lb_socket, client_socket;
    struct sockaddr_in lb_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Daemonize the process
    daemonize();

    // Create load balancer socket
    lb_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (lb_socket == -1) {
        log_message("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the load balancer socket to port 7070
    memset(&lb_addr, 0, sizeof(lb_addr));
    lb_addr.sin_family = AF_INET;
    lb_addr.sin_addr.s_addr = INADDR_ANY;
    lb_addr.sin_port = htons(7070);

    if (bind(lb_socket, (struct sockaddr *)&lb_addr, sizeof(lb_addr)) < 0) {
        log_message("Bind failed");
        close(lb_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(lb_socket, 5) < 0) {
        log_message("Listen failed");
        close(lb_socket);
        exit(EXIT_FAILURE);
    }

    log_message("Load balancer listening on port 7070...");

    while (1) {
        // Accept a new client connection
        client_socket = accept(lb_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) {
            log_message("Accept failed");
            continue;
        }

        log_message("New connection accepted");

        // Create a new thread to handle the client connection
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, &client_socket) != 0) {
            log_message("Failed to create thread");
            close(client_socket);
            continue;
        }

        // Detach the thread to allow it to clean up automatically
        pthread_detach(thread_id);
    }

    // Close the load balancer socket
    close(lb_socket);

    return 0;
}
