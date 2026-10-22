//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_PROFILE_H
#define GOPHER_PROFILE_H

#include "common.h"

typedef struct {
    uint32_t type;
    char   **addresses;
    size_t   addr_count;

    // TCP fields
    int      banner_size;
    bool     use_ssl;
    uint8_t *ssl_cert;
    size_t   ssl_cert_len;
    uint8_t *ssl_key;
    size_t   ssl_key_len;
    uint8_t *ca_cert;
    size_t   ca_cert_len;

    // HTTP fields
    char    *http_method;
    char   **uris;
    size_t   uri_count;
    char   **user_agents;
    size_t   ua_count;
    char   **host_headers;
    size_t   hh_count;
    char    *hb_header;
    char    *request_headers;
    int      sleep_interval;
    uint32_t ans_pre_size;
    uint32_t ans_size;
    uint8_t  rotation_mode;

    // Shared
    int      conn_timeout;
    int      conn_count;
} Profile;

typedef struct {
    char    *process;
    int      pid;
    char    *user;
    char    *host;
    char    *ipaddr;
    bool     elevated;
    uint32_t acp;
    uint32_t oem;
    char    *os;
    char    *os_version;
    uint8_t  encrypt_key[16];
} SessionInfo;

typedef struct {
    int8_t   type;
    uint8_t **objects;
    size_t   *object_lens;
    size_t    object_count;
} Message;

typedef struct {
    uint32_t code;
    uint32_t id;
    uint8_t *data;
    size_t   data_len;
} Command;

typedef struct {
    uint32_t id;
    uint32_t type;
    uint8_t *data;
    size_t   data_len;
} InitPack;

typedef struct {
    int      type;
    uint8_t *data;
    size_t   data_len;
} StartMsg;

#endif
