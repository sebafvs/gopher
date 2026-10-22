//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_NET_HTTP_H
#define GOPHER_NET_HTTP_H

#include "common.h"
#include "profile.h"

typedef struct HttpCtx HttpCtx;

HttpCtx *http_init  (void);

int http_set_profile(HttpCtx *ctx, const Profile *prof, const uint8_t *beat_hdr_val, size_t beat_hdr_len);
int http_exchange   (HttpCtx *ctx, const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);

void http_free      (HttpCtx *ctx);

#endif
