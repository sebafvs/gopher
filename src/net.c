//
// Created by seba on 10/17/26.
//

#include "net.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

int net_connect(const char *host, uint16_t port) {
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;    // IPv4 or IPv6, whichever resolves
    hints.ai_socktype = SOCK_STREAM;  // TCP

    struct addrinfo *res = NULL;
    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        DBG("getaddrinfo(%s:%u): %s\n", host, port, gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int ret;
        do {
            ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
        } while (ret < 0 && errno == EINTR);

        if (ret == 0) break;  // connected

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0) DBG("connect(%s:%u) failed\n", host, port);
    else        DBG("connected to %s:%u (fd=%d)\n", host, port, fd);

    return fd;
}

void net_close(int fd) {
    if (fd >= 0) close(fd);
}

int net_recv_exact(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;  // error or peer closed
        got += (size_t)n;
    }
    return 0;
}

static int net_send_exact(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

int net_recv_msg(int fd, uint8_t **out, uint32_t *out_len) {
    uint8_t hdr[4];
    if (net_recv_exact(fd, hdr, 4) < 0) return -1;

    uint32_t payload_len = ((uint32_t)hdr[0] << 24)
                         | ((uint32_t)hdr[1] << 16)
                         | ((uint32_t)hdr[2] <<  8)
                         | ((uint32_t)hdr[3]);

    if (payload_len == 0) {
        *out     = NULL;
        *out_len = 0;
        return 0;
    }

    uint8_t *payload = malloc(payload_len);
    if (!payload) return -1;

    if (net_recv_exact(fd, payload, payload_len) < 0) {
        free(payload);
        return -1;
    }

    *out     = payload;
    *out_len = payload_len;
    return (int)payload_len;
}

int net_send_msg(int fd, const uint8_t *data, uint32_t len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(len >> 24);
    hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >>  8);
    hdr[3] = (uint8_t)(len);

    if (net_send_exact(fd, hdr, 4) < 0) return -1;
    if (len > 0 && net_send_exact(fd, data, len) < 0) return -1;
    return 0;
}

int net_connect_timeout(const char *host, uint16_t port, int timeout_ms, int *reason_out) {
    if (reason_out) *reason_out = 0;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        DBG("getaddrinfo(%s:%u): %s\n", host, port, gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            fcntl(fd, F_SETFL, flags);
            break;
        }
        if (errno != EINPROGRESS) {
            if (reason_out) {
                if (errno == ECONNREFUSED) *reason_out = 5;
                else if (errno == ENETUNREACH) *reason_out = 3;
            }
            close(fd); fd = -1;
            continue;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) {
            if (reason_out) *reason_out = 4;
            close(fd); fd = -1;
            continue;
        }

        int so_err = 0;
        socklen_t so_len = sizeof(so_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
        if (so_err != 0) {
            if (reason_out) {
                if (so_err == ECONNREFUSED) *reason_out = 5;
                else if (so_err == ENETUNREACH) *reason_out = 3;
            }
            close(fd); fd = -1;
            continue;
        }

        fcntl(fd, F_SETFL, flags);
        break;
    }

    freeaddrinfo(res);
    return fd;
}
