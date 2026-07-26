#include "http.h"

#include "config.h"
#include "handlers.h"
#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uv.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* Idle time a keep-alive connection may sit without sending a request. */
#define HTTP_CLIENT_TIMEOUT_SEC 30
/* Upper bound on how long a single response write may stall. */
#define HTTP_WRITE_TIMEOUT_MS 10000
#define HTTP_LISTEN_BACKLOG 128

static volatile sig_atomic_t *s_running = NULL;

static int wait_writable(int fd, int timeout_ms) {
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000;

    return select(fd + 1, NULL, &wfds, NULL, &tv);
}

/*
 * Responses are written straight to the socket from the thread handling the
 * request, which keeps the streaming export (an arbitrarily large body) simple.
 * The event loop has stopped reading the connection for the duration, so it
 * never touches the fd concurrently. libuv sockets are non-blocking, hence the
 * explicit wait-then-send loop.
 */
int http_write_all(int fd, const void *data, size_t len) {
    const char *p = data;
    size_t left = len;

    while (left > 0) {
        if (s_running && !*s_running) {
            return -1;
        }
        ssize_t n = send(fd, p, left, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_writable(fd, HTTP_WRITE_TIMEOUT_MS) <= 0) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        p += n;
        left -= (size_t)n;
    }
    return 0;
}

static const char *find_header_end(const char *buf, size_t total) {
    for (size_t i = 0; i + 3 < total; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static int header_has_chunked(const char *buf, const char *hdr_end) {
    for (const char *p = buf; p < hdr_end; p++) {
        if (strncasecmp(p, "Transfer-Encoding:", 18) == 0) {
            const char *v = p + 18;
            while (*v == ' ') {
                v++;
            }
            if (strncasecmp(v, "chunked", 7) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int chunked_body_complete(const char *buf, size_t total, size_t hdr_len) {
    const char *body = buf + hdr_len;
    size_t body_len = total - hdr_len;
    if (body_len < 5) {
        return 0;
    }
    for (size_t i = 0; i + 4 < body_len; i++) {
        if (body[i] == '0' && body[i + 1] == '\r' && body[i + 2] == '\n' &&
            body[i + 3] == '\r' && body[i + 4] == '\n') {
            return 1;
        }
    }
    return 0;
}

static int request_complete(const char *buf, size_t total, size_t *msg_len) {
    const char *hdr_end = find_header_end(buf, total);
    if (!hdr_end) {
        return 0;
    }

    size_t hdr_len = (size_t)(hdr_end - buf) + 4;
    size_t content_len = 0;
    int has_cl = 0;

    for (const char *p = buf; p < hdr_end; p++) {
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            const char *v = p + 15;
            while (*v == ' ') {
                v++;
            }
            content_len = (size_t)atoi(v);
            has_cl = 1;
            break;
        }
    }

    if (!has_cl && header_has_chunked(buf, hdr_end)) {
        if (!chunked_body_complete(buf, total, hdr_len)) {
            return 0;
        }
        *msg_len = total;
        return 1;
    }

    if (!has_cl) {
        *msg_len = hdr_len;
        return total >= hdr_len;
    }

    *msg_len = hdr_len + content_len;
    return total >= *msg_len;
}

static int should_keep_alive(const http_request_t *req) {
    const char *conn = http_get_header(req, "Connection");
    if (conn) {
        if (strcasecmp(conn, "close") == 0) {
            return 0;
        }
        if (strcasecmp(conn, "keep-alive") == 0) {
            return 1;
        }
    }
    return req->http_minor >= 1;
}

static void strtolower(char *s) {
    for (; *s; s++) {
        *s = (char)tolower((unsigned char)*s);
    }
}

const char *http_get_header(const http_request_t *req, const char *name) {
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].name, name) == 0) {
            return req->headers[i].value;
        }
    }
    return NULL;
}

void http_normalize_path(const char *url_path, char *out, size_t outlen) {
    const char *path = url_path ? url_path : "/";
    const char *q = strchr(path, '?');
    size_t len = q ? (size_t)(q - path) : strlen(path);
    if (len >= outlen) {
        len = outlen - 1;
    }
    memcpy(out, path, len);
    out[len] = '\0';
    while (len > 1 && out[len - 1] == '/') {
        out[--len] = '\0';
    }
    if (out[0] == '\0') {
        strncpy(out, "/", outlen - 1);
    }
}

int http_query_param(const char *url_path, const char *key, char *out, size_t outlen) {
    if (out && outlen) {
        out[0] = '\0';
    }
    if (!url_path || !key || !key[0] || !out || outlen == 0) {
        return 0;
    }
    const char *q = strchr(url_path, '?');
    if (!q || !q[1]) {
        return 0;
    }
    size_t key_len = strlen(key);
    const char *p = q + 1;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t pair_len = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', pair_len);
        size_t name_len = eq ? (size_t)(eq - p) : pair_len;
        if (name_len == key_len && strncmp(p, key, key_len) == 0) {
            const char *val = eq ? eq + 1 : p + name_len;
            size_t val_len = pair_len - name_len - (eq ? 1 : 0);
            if (val_len >= outlen) {
                val_len = outlen - 1;
            }
            memcpy(out, val, val_len);
            out[val_len] = '\0';
            return 1;
        }
        if (!amp) {
            break;
        }
        p = amp + 1;
    }
    return 0;
}

static int header_line(const char *line, http_header_t *hdr) {
    const char *colon = strchr(line, ':');
    if (!colon) {
        return -1;
    }
    size_t nlen = (size_t)(colon - line);
    if (nlen >= HTTP_HEADER_NAME_LEN) {
        nlen = HTTP_HEADER_NAME_LEN - 1;
    }
    memcpy(hdr->name, line, nlen);
    hdr->name[nlen] = '\0';
    const char *val = colon + 1;
    while (*val == ' ') {
        val++;
    }
    strncpy(hdr->value, val, HTTP_HEADER_VALUE_LEN - 1);
    hdr->value[HTTP_HEADER_VALUE_LEN - 1] = '\0';
    return 0;
}

static size_t decode_chunked_body(const char *raw, size_t raw_len, size_t body_off, char *out,
                                  size_t outlen) {
    size_t out_pos = 0;
    size_t pos = body_off;

    while (pos < raw_len) {
        size_t line_end = pos;
        while (line_end + 1 < raw_len && !(raw[line_end] == '\r' && raw[line_end + 1] == '\n')) {
            line_end++;
        }
        if (line_end + 1 >= raw_len) {
            break;
        }

        char size_buf[16];
        size_t size_len = line_end - pos;
        if (size_len == 0 || size_len >= sizeof(size_buf)) {
            break;
        }
        memcpy(size_buf, raw + pos, size_len);
        size_buf[size_len] = '\0';

        size_t chunk_size = (size_t)strtoul(size_buf, NULL, 16);
        pos = line_end + 2;
        if (chunk_size == 0) {
            break;
        }
        if (pos + chunk_size > raw_len) {
            break;
        }
        if (out_pos + chunk_size >= outlen) {
            break;
        }
        memcpy(out + out_pos, raw + pos, chunk_size);
        out_pos += chunk_size;
        pos += chunk_size;
        if (pos + 1 < raw_len && raw[pos] == '\r' && raw[pos + 1] == '\n') {
            pos += 2;
        }
    }

    if (out_pos < outlen) {
        out[out_pos] = '\0';
    }
    return out_pos;
}

int http_parse_request(const char *raw, size_t raw_len, http_request_t *req) {
    memset(req, 0, sizeof(*req));
    const char *hdr_end = find_header_end(raw, raw_len);
    if (!hdr_end) {
        return -1;
    }

    char first[1024];
    size_t first_len = (size_t)(hdr_end - raw);
    if (first_len >= sizeof(first)) {
        first_len = sizeof(first) - 1;
    }
    memcpy(first, raw, first_len);
    first[first_len] = '\0';

    char *save = NULL;
    char *line = strtok_r(first, "\r\n", &save);
    if (!line) {
        return -1;
    }
    char method[16], path[HTTP_MAX_PATH], version[16];
    if (sscanf(line, "%15s %511s %15s", method, path, version) < 2) {
        return -1;
    }
    util_strlcpy(req->method, method, sizeof(req->method));
    util_strlcpy(req->path, path, sizeof(req->path));
    req->http_minor = 0;
    if (sscanf(version, "HTTP/%*d.%d", &req->http_minor) != 1) {
        req->http_minor = 1;
    }

    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        if (req->header_count >= HTTP_MAX_HEADERS) {
            break;
        }
        if (header_line(line, &req->headers[req->header_count]) == 0) {
            req->header_count++;
        }
    }

    size_t body_off = (size_t)(hdr_end - raw) + 4;
    if (body_off < raw_len) {
        size_t blen;
        if (header_has_chunked(raw, hdr_end)) {
            blen = decode_chunked_body(raw, raw_len, body_off, req->body, sizeof(req->body));
        } else {
            blen = raw_len - body_off;
            if (blen >= HTTP_MAX_BODY) {
                blen = HTTP_MAX_BODY - 1;
            }
            memcpy(req->body, raw + body_off, blen);
            req->body[blen] = '\0';
        }
        req->body_len = blen;
    }

    const char *cl = http_get_header(req, "Content-Length");
    if (cl) {
        size_t expected = (size_t)atoi(cl);
        if (expected > req->body_len && expected < HTTP_MAX_BODY) {
            /* body may be incomplete in buffer; best effort for small requests */
        }
    }
    return 0;
}

void http_parse_body(const char *raw, size_t raw_len, const char *content_type, char *json_out,
                     size_t json_outlen) {
    (void)raw_len;
    if (!raw || !raw[0]) {
        json_out[0] = '\0';
        return;
    }
    char ct[128];
    strncpy(ct, content_type ? content_type : "", sizeof(ct) - 1);
    strtolower(ct);

    if (strstr(ct, "application/json")) {
        strncpy(json_out, raw, json_outlen - 1);
        json_out[json_outlen - 1] = '\0';
        return;
    }
    if (strstr(ct, "application/x-www-form-urlencoded")) {
        json_out[0] = '{';
        json_out[1] = '\0';
        return;
    }
    strncpy(json_out, raw, json_outlen - 1);
    json_out[json_outlen - 1] = '\0';
}

int http_parse_basic_auth(const http_request_t *req, char *client_id, size_t id_len,
                          char *client_secret, size_t secret_len) {
    const char *auth = http_get_header(req, "Authorization");
    if (!auth || strncasecmp(auth, "Basic ", 6) != 0) {
        return -1;
    }
    char decoded[512];
    if (util_base64_decode(auth + 6, decoded, sizeof(decoded)) < 0) {
        return -1;
    }
    char *colon = strchr(decoded, ':');
    if (!colon) {
        strncpy(client_id, decoded, id_len - 1);
        client_id[id_len - 1] = '\0';
        client_secret[0] = '\0';
        return 0;
    }
    *colon = '\0';
    strncpy(client_id, decoded, id_len - 1);
    client_id[id_len - 1] = '\0';
    strncpy(client_secret, colon + 1, secret_len - 1);
    client_secret[secret_len - 1] = '\0';
    return 0;
}

int http_parse_bearer(const http_request_t *req, char *token, size_t token_len) {
    const char *auth = http_get_header(req, "Authorization");
    if (!auth || strncasecmp(auth, "Bearer ", 7) != 0) {
        return -1;
    }
    const char *t = auth + 7;
    while (*t == ' ') {
        t++;
    }
    strncpy(token, t, token_len - 1);
    token[token_len - 1] = '\0';
    return token[0] ? 0 : -1;
}

void http_send_response(int client_fd, const http_response_t *res, int keep_alive) {
    char header[1024];
    char combined[HTTP_MAX_BODY + 2048];
    size_t header_len;
    size_t total_len;
    const char *connection = keep_alive ? "keep-alive" : "close";

    if (res->no_body) {
        header_len = (size_t)snprintf(header, sizeof(header),
                                      "HTTP/1.1 %d No Content\r\n"
                                      "Access-Control-Allow-Origin: *\r\n"
                                      "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
                                      "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                                      "Connection: %s\r\n\r\n",
                                      res->status, connection);
        http_write_all(client_fd, header, header_len);
        return;
    }

    if (res->stream) {
        const char *ct = res->stream_content_type[0] ? res->stream_content_type
                                                         : "text/plain; charset=utf-8";
        header_len = (size_t)snprintf(
            header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
            "Connection: close\r\n\r\n",
            ct);
        http_write_all(client_fd, header, header_len);
        if (res->stream_fn) {
            res->stream_fn(client_fd, res->stream_ctx);
        }
        return;
    }

    const char *status_text = "OK";
    if (res->status == 400) {
        status_text = "Bad Request";
    } else if (res->status == 401) {
        status_text = "Unauthorized";
    } else if (res->status == 404) {
        status_text = "Not Found";
    } else if (res->status == 500) {
        status_text = "Internal Server Error";
    }

    header_len = (size_t)snprintf(header, sizeof(header),
                                  "HTTP/1.1 %d %s\r\n"
                                  "Content-Type: application/json; charset=utf-8\r\n"
                                  "Content-Length: %zu\r\n"
                                  "Access-Control-Allow-Origin: *\r\n"
                                  "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
                                  "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                                  "Connection: %s\r\n\r\n",
                                  res->status, status_text, res->body_len, connection);
    total_len = header_len + res->body_len;
    if (total_len <= sizeof(combined)) {
        memcpy(combined, header, header_len);
        if (res->body_len > 0) {
            memcpy(combined + header_len, res->body, res->body_len);
        }
        http_write_all(client_fd, combined, total_len);
        return;
    }

    http_write_all(client_fd, header, header_len);
    if (res->body_len > 0) {
        http_write_all(client_fd, res->body, res->body_len);
    }
}

void http_send_json(int client_fd, int status, const char *json) {
    http_response_t res = {0};
    res.status = status;
    res.body_len = strlen(json);
    strncpy(res.body, json, sizeof(res.body) - 1);
    http_send_response(client_fd, &res, 0);
}

/*
 * ── Connection handling ────────────────────────────────────────────────────
 *
 * A libuv event loop owns every socket. Accepting, reading and the idle
 * timeout all happen on the loop thread and never block, so any number of
 * clients can be connected at once. As soon as a full request has arrived the
 * connection is handed to the libuv thread pool, because handlers block: they
 * hit SQLite and, in hardware mode, wait on the serialised WORM worker for
 * seconds at a time. The loop thread stays free to serve everyone else while
 * that happens.
 *
 * Reading is stopped while a request is in flight, so one connection never has
 * more than one outstanding job and requests on a connection stay ordered.
 */

#define CONN_READ_CHUNK 8192
#define CONN_MAX_BUFFER (HTTP_MAX_BODY + 16384)

typedef struct {
    uv_tcp_t   handle;
    uv_timer_t idle;
    uv_work_t  work;

    char  *buf;
    size_t len;
    size_t cap;
    size_t msg_len;

    http_request_t  *req;
    http_response_t *res;

    int fd;
    int keep_alive;
    int bad_request;
    int processing; /* a thread-pool job owns the fd right now */
    int closing;    /* close requested; deferred while processing */
    int closed;
    int handles_open;
} conn_t;

static uv_loop_t  s_loop;
static uv_tcp_t   s_server;
static uv_async_t s_stop_async;
static int        s_loop_ready = 0;

static void conn_start_reading(conn_t *c);

static void on_handle_closed(uv_handle_t *handle) {
    conn_t *c = handle->data;
    if (--c->handles_open > 0) {
        return;
    }
    free(c->buf);
    free(c->req);
    free(c->res);
    free(c);
}

static void conn_close(conn_t *c) {
    c->closing = 1;
    if (c->closed) {
        return;
    }
    /*
     * Closing the handle closes the fd, and a thread-pool job may still be
     * writing the response to it. Let after_work_cb finish the close instead.
     */
    if (c->processing) {
        return;
    }
    c->closed = 1;
    uv_timer_stop(&c->idle);
    if (!uv_is_closing((uv_handle_t *)&c->idle)) {
        uv_close((uv_handle_t *)&c->idle, on_handle_closed);
    }
    if (!uv_is_closing((uv_handle_t *)&c->handle)) {
        uv_read_stop((uv_stream_t *)&c->handle);
        uv_close((uv_handle_t *)&c->handle, on_handle_closed);
    }
}

static void on_idle_timeout(uv_timer_t *timer) {
    conn_close(timer->data);
}

static void alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)suggested;
    conn_t *c = handle->data;

    if (c->len + CONN_READ_CHUNK + 1 > c->cap) {
        size_t want = c->cap ? c->cap * 2 : CONN_READ_CHUNK * 2;
        while (want < c->len + CONN_READ_CHUNK + 1) {
            want *= 2;
        }
        if (want > CONN_MAX_BUFFER) {
            want = CONN_MAX_BUFFER;
        }
        if (want > c->cap) {
            char *grown = realloc(c->buf, want);
            if (!grown) {
                buf->base = NULL;
                buf->len = 0;
                return;
            }
            c->buf = grown;
            c->cap = want;
        }
    }

    size_t space = (c->cap > c->len + 1) ? c->cap - c->len - 1 : 0;
    buf->base = c->buf + c->len;
    buf->len = space;
}

/* Runs on a thread-pool thread: route the request and write the response. */
static void work_cb(uv_work_t *work) {
    conn_t *c = work->data;

    if (c->bad_request) {
        http_send_json(c->fd, 400,
                       "{\"error\":\"bad_request\",\"message\":\"Invalid HTTP request\"}");
        c->keep_alive = 0;
        return;
    }

    if (http_parse_request(c->buf, c->msg_len, c->req) != 0) {
        http_send_json(c->fd, 400,
                       "{\"error\":\"bad_request\",\"message\":\"Invalid HTTP request\"}");
        c->keep_alive = 0;
        return;
    }

    const char *ct = http_get_header(c->req, "Content-Type");
    char *parsed_body = malloc(HTTP_MAX_BODY);
    if (parsed_body) {
        http_parse_body(c->req->body, c->req->body_len, ct ? ct : "", parsed_body, HTTP_MAX_BODY);
        if (parsed_body[0]) {
            util_strlcpy(c->req->body, parsed_body, sizeof(c->req->body));
            c->req->body_len = strlen(c->req->body);
        }
        free(parsed_body);
    }

    handlers_route(c->req, c->res);
    c->keep_alive = should_keep_alive(c->req);
    /* Streamed bodies have no Content-Length, so the close delimits them. */
    if (c->res->stream) {
        c->keep_alive = 0;
    }
    http_send_response(c->fd, c->res, c->keep_alive);
}

static void after_work_cb(uv_work_t *work, int status) {
    conn_t *c = work->data;
    c->processing = 0;

    if (status == UV_ECANCELED || c->closing || !c->keep_alive || (s_running && !*s_running)) {
        conn_close(c);
        return;
    }

    /* Carry over anything the client pipelined behind this request. */
    if (c->len > c->msg_len) {
        memmove(c->buf, c->buf + c->msg_len, c->len - c->msg_len);
        c->len -= c->msg_len;
    } else {
        c->len = 0;
    }
    c->msg_len = 0;

    conn_start_reading(c);
}

static void dispatch_request(conn_t *c) {
    uv_read_stop((uv_stream_t *)&c->handle);
    uv_timer_stop(&c->idle);

    if (uv_fileno((uv_handle_t *)&c->handle, &c->fd) != 0) {
        conn_close(c);
        return;
    }

    if (!c->req) {
        c->req = malloc(sizeof(*c->req));
    }
    if (!c->res) {
        c->res = malloc(sizeof(*c->res));
    }
    if (!c->req || !c->res) {
        conn_close(c);
        return;
    }
    memset(c->res, 0, sizeof(*c->res));

    c->work.data = c;
    c->processing = 1;
    if (uv_queue_work(&s_loop, &c->work, work_cb, after_work_cb) != 0) {
        c->processing = 0;
        conn_close(c);
    }
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)buf;
    conn_t *c = stream->data;

    if (nread < 0) {
        conn_close(c);
        return;
    }
    if (nread == 0) {
        return;
    }

    c->len += (size_t)nread;
    c->buf[c->len] = '\0';

    size_t msg_len = 0;
    if (request_complete(c->buf, c->len, &msg_len)) {
        c->msg_len = msg_len;
        dispatch_request(c);
        return;
    }

    if (c->len + 1 >= CONN_MAX_BUFFER) {
        c->bad_request = 1;
        dispatch_request(c);
    }
}

static void conn_start_reading(conn_t *c) {
    if (c->closing) {
        return;
    }

    /* A pipelined request may already be sitting in the buffer. */
    size_t msg_len = 0;
    if (c->len > 0 && request_complete(c->buf, c->len, &msg_len)) {
        c->msg_len = msg_len;
        dispatch_request(c);
        return;
    }

    uv_timer_start(&c->idle, on_idle_timeout, HTTP_CLIENT_TIMEOUT_SEC * 1000, 0);
    if (uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read) != 0) {
        conn_close(c);
    }
}

static void on_connection(uv_stream_t *server, int status) {
    if (status != 0) {
        log_error("accept: %s", uv_strerror(status));
        return;
    }

    conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return;
    }
    c->keep_alive = 1;
    c->fd = -1;

    if (uv_tcp_init(&s_loop, &c->handle) != 0) {
        free(c);
        return;
    }
    c->handle.data = c;
    c->handles_open = 1;

    if (uv_accept(server, (uv_stream_t *)&c->handle) != 0) {
        uv_close((uv_handle_t *)&c->handle, on_handle_closed);
        return;
    }

    uv_tcp_nodelay(&c->handle, 1);
    uv_timer_init(&s_loop, &c->idle);
    c->idle.data = c;
    c->handles_open = 2;

    conn_start_reading(c);
}

/* ── Shutdown ──────────────────────────────────────────────────────────── */

static void close_walk_cb(uv_handle_t *handle, void *arg) {
    (void)arg;
    if (uv_is_closing(handle)) {
        return;
    }
    if (handle == (uv_handle_t *)&s_server || handle == (uv_handle_t *)&s_stop_async) {
        uv_close(handle, NULL);
        return;
    }
    if (handle->data) {
        conn_close(handle->data);
    }
}

static void on_stop_async(uv_async_t *async) {
    (void)async;
    uv_walk(&s_loop, close_walk_cb, NULL);
}

void http_shutdown(void) {
    /* Called from a signal handler; uv_async_send is async-signal-safe. */
    if (s_loop_ready) {
        uv_async_send(&s_stop_async);
    }
}

int http_serve(const char *host, uint16_t port, volatile sig_atomic_t *running) {
    s_running = running;

    if (uv_loop_init(&s_loop) != 0) {
        log_error("uv_loop_init failed");
        return -1;
    }
    if (uv_tcp_init(&s_loop, &s_server) != 0) {
        log_error("uv_tcp_init failed");
        uv_loop_close(&s_loop);
        return -1;
    }
    s_server.data = NULL;

    if (uv_async_init(&s_loop, &s_stop_async, on_stop_async) != 0) {
        log_error("uv_async_init failed");
        uv_loop_close(&s_loop);
        return -1;
    }
    s_stop_async.data = NULL;
    s_loop_ready = 1;

    struct sockaddr_in addr;
    if (uv_ip4_addr(host, port, &addr) != 0) {
        uv_ip4_addr("0.0.0.0", port, &addr);
    }

    int rc = uv_tcp_bind(&s_server, (const struct sockaddr *)&addr, 0);
    if (rc != 0) {
        log_error("bind %s:%u: %s", host, port, uv_strerror(rc));
        goto fail;
    }

    rc = uv_listen((uv_stream_t *)&s_server, HTTP_LISTEN_BACKLOG, on_connection);
    if (rc != 0) {
        log_error("listen: %s", uv_strerror(rc));
        goto fail;
    }

    /* A signal may have arrived before the async handle existed. */
    if (s_running && !*s_running) {
        uv_walk(&s_loop, close_walk_cb, NULL);
    }

    uv_run(&s_loop, UV_RUN_DEFAULT);

    uv_walk(&s_loop, close_walk_cb, NULL);
    uv_run(&s_loop, UV_RUN_DEFAULT);
    s_loop_ready = 0;
    uv_loop_close(&s_loop);
    return 0;

fail:
    s_loop_ready = 0;
    uv_close((uv_handle_t *)&s_server, NULL);
    uv_close((uv_handle_t *)&s_stop_async, NULL);
    uv_run(&s_loop, UV_RUN_DEFAULT);
    uv_loop_close(&s_loop);
    return -1;
}
