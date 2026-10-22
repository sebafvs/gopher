//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_NET_H
#define GOPHER_NET_H

#include "common.h"

int  net_connect   (const char *host, uint16_t port);
void net_close     (int fd);
int  net_recv_exact(int fd, uint8_t *buf, size_t len);
int  net_recv_msg  (int fd, uint8_t **out, uint32_t *out_len);
int  net_send_msg  (int fd, const uint8_t *data, uint32_t len);
int  net_connect_timeout(const char *host, uint16_t port, int timeout_ms, int *reason_out);

#endif
