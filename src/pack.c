//
// Created by seba on 10/17/26.
//

#include "pack.h"

#include <stdlib.h>
#include <string.h>
#include "../lib/mpack/mpack.h"

// Helper: duplicate a string from mpack node
static char *node_strdup(mpack_node_t node) {
    if (mpack_node_is_missing(node) || mpack_node_type(node) == mpack_type_nil) return NULL;
    size_t len = mpack_node_strlen(node);
    const char *s = mpack_node_str(node);
    if (!s || len == 0) return NULL;
    char *dup = malloc(len + 1);
    if (!dup) return NULL;
    memcpy(dup, s, len);
    dup[len] = '\0';
    return dup;
}

// Helper: duplicate binary data from mpack node (nil-safe)
static uint8_t *node_bindup(mpack_node_t node, size_t *out_len) {
    *out_len = 0;
    if (mpack_node_is_missing(node) || mpack_node_type(node) == mpack_type_nil) return NULL;
    size_t len = mpack_node_bin_size(node);
    const char *d = mpack_node_bin_data(node);
    *out_len = len;
    if (!d || len == 0) return NULL;
    uint8_t *dup = malloc(len);
    if (!dup) return NULL;
    memcpy(dup, d, len);
    return dup;
}

static char **node_strarray(mpack_node_t node, size_t *count) {
    *count = 0;
    if (mpack_node_is_missing(node) || mpack_node_type(node) == mpack_type_nil) return NULL;
    *count = mpack_node_array_length(node);
    if (*count == 0) return NULL;
    char **arr = calloc(*count, sizeof(char *));
    for (size_t i = 0; i < *count; i++)
        arr[i] = node_strdup(mpack_node_array_at(node, i));
    return arr;
}


static int32_t node_i32_or(mpack_node_t node, int32_t def) {
    if (mpack_node_is_missing(node) || mpack_node_type(node) == mpack_type_nil) return def;
    return mpack_node_i32(node);
}

static uint32_t node_u32_or(mpack_node_t node, uint32_t def) {
    if (mpack_node_is_missing(node) || mpack_node_type(node) == mpack_type_nil) return def;
    return mpack_node_u32(node);
}

static uint8_t node_u8_or(mpack_node_t node, uint8_t def) {
    if (mpack_node_is_missing(node) || mpack_node_type(node) == mpack_type_nil) return def;
    return mpack_node_u8(node);
}

static void free_strarray(char **arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; i++) free(arr[i]);
    free(arr);
}

int pack_decode_profile(const uint8_t *data, size_t len, Profile *out) {
    memset(out, 0, sizeof(*out));

    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    out->type         = mpack_node_u32(mpack_node_map_cstr(root, "type"));
    out->conn_timeout = mpack_node_i32(mpack_node_map_cstr(root, "conn_timeout"));
    out->conn_count   = mpack_node_i32(mpack_node_map_cstr(root, "conn_count"));
    out->use_ssl      = mpack_node_bool(mpack_node_map_cstr(root, "use_ssl"));
    out->addresses    = node_strarray(mpack_node_map_cstr(root, "addresses"), &out->addr_count);

    out->banner_size    = node_i32_or(mpack_node_map_cstr_optional(root, "banner_size"), 0);
    out->ssl_cert       = node_bindup(mpack_node_map_cstr_optional(root, "ssl_cert"), &out->ssl_cert_len);
    out->ssl_key        = node_bindup(mpack_node_map_cstr_optional(root, "ssl_key"),  &out->ssl_key_len);
    out->ca_cert        = node_bindup(mpack_node_map_cstr_optional(root, "ca_cert"),  &out->ca_cert_len);

    out->sleep_interval = node_i32_or(mpack_node_map_cstr_optional(root, "sleep_interval"), 0);
    out->ans_pre_size   = node_u32_or(mpack_node_map_cstr_optional(root, "ans_pre_size"), 0);
    out->ans_size       = node_u32_or(mpack_node_map_cstr_optional(root, "ans_size"), 0);
    out->rotation_mode  = node_u8_or(mpack_node_map_cstr_optional(root, "rotation_mode"), 0);
    out->uris           = node_strarray(mpack_node_map_cstr_optional(root, "uris"), &out->uri_count);
    out->user_agents    = node_strarray(mpack_node_map_cstr_optional(root, "user_agents"), &out->ua_count);
    out->host_headers   = node_strarray(mpack_node_map_cstr_optional(root, "host_headers"), &out->hh_count);
    out->http_method    = node_strdup(mpack_node_map_cstr_optional(root, "http_method"));
    out->hb_header      = node_strdup(mpack_node_map_cstr_optional(root, "hb_header"));
    out->request_headers = node_strdup(mpack_node_map_cstr_optional(root, "request_headers"));

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

void profile_free(Profile *p) {
    free_strarray(p->addresses, p->addr_count);
    free_strarray(p->uris, p->uri_count);
    free_strarray(p->user_agents, p->ua_count);
    free_strarray(p->host_headers, p->hh_count);
    free(p->http_method);
    free(p->hb_header);
    free(p->request_headers);
    free(p->ssl_cert);
    free(p->ssl_key);
    free(p->ca_cert);
    memset(p, 0, sizeof(*p));
}

int pack_encode_session_info(const SessionInfo *info, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 11);

    mpack_write_cstr(&writer, "process");
    mpack_write_cstr(&writer, info->process ? info->process : "");

    mpack_write_cstr(&writer, "pid");
    mpack_write_i32(&writer, info->pid);

    mpack_write_cstr(&writer, "user");
    mpack_write_cstr(&writer, info->user ? info->user : "");

    mpack_write_cstr(&writer, "host");
    mpack_write_cstr(&writer, info->host ? info->host : "");

    mpack_write_cstr(&writer, "ipaddr");
    mpack_write_cstr(&writer, info->ipaddr ? info->ipaddr : "");

    mpack_write_cstr(&writer, "elevated");
    mpack_write_bool(&writer, info->elevated);

    mpack_write_cstr(&writer, "acp");
    mpack_write_u32(&writer, info->acp);

    mpack_write_cstr(&writer, "oem");
    mpack_write_u32(&writer, info->oem);

    mpack_write_cstr(&writer, "os");
    mpack_write_cstr(&writer, info->os ? info->os : "");

    mpack_write_cstr(&writer, "os_version");
    mpack_write_cstr(&writer, info->os_version ? info->os_version : "");

    mpack_write_cstr(&writer, "encrypt_key");
    mpack_write_bin(&writer, (const char *)info->encrypt_key, 16);

    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }

    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_init_pack(const InitPack *ip, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 3);

    mpack_write_cstr(&writer, "id");
    mpack_write_u32(&writer, ip->id);

    mpack_write_cstr(&writer, "type");
    mpack_write_u32(&writer, ip->type);

    mpack_write_cstr(&writer, "data");
    mpack_write_bin(&writer, (const char *)ip->data, ip->data_len);

    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }

    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_start_msg(const StartMsg *sm, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 2);

    mpack_write_cstr(&writer, "id");
    mpack_write_i32(&writer, sm->type);

    mpack_write_cstr(&writer, "data");
    mpack_write_bin(&writer, (const char *)sm->data, sm->data_len);

    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }

    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_message(const Message *msg, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 2);

    mpack_write_cstr(&writer, "type");
    mpack_write_i8(&writer, msg->type);

    mpack_write_cstr(&writer, "object");
    mpack_start_array(&writer, (uint32_t)msg->object_count);
    for (size_t i = 0; i < msg->object_count; i++)
        mpack_write_bin(&writer, (const char *)msg->objects[i], msg->object_lens[i]);
    mpack_finish_array(&writer);

    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }

    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_decode_message(const uint8_t *data, size_t len, Message *out) {
    memset(out, 0, sizeof(*out));

    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    out->type = mpack_node_i8(mpack_node_map_cstr(root, "type"));

    mpack_node_t arr = mpack_node_map_cstr(root, "object");
    out->object_count = mpack_node_array_length(arr);
    if (out->object_count > 0) {
        out->objects     = calloc(out->object_count, sizeof(uint8_t *));
        out->object_lens = calloc(out->object_count, sizeof(size_t));
        for (size_t i = 0; i < out->object_count; i++)
            out->objects[i] = node_bindup(mpack_node_array_at(arr, i), &out->object_lens[i]);
    }

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

void message_free(Message *msg) {
    if (msg->objects) {
        for (size_t i = 0; i < msg->object_count; i++) free(msg->objects[i]);
        free(msg->objects);
    }
    free(msg->object_lens);
    memset(msg, 0, sizeof(*msg));
}

int pack_decode_command(const uint8_t *data, size_t len, Command *out) {
    memset(out, 0, sizeof(*out));

    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    out->code = mpack_node_u32(mpack_node_map_cstr(root, "code"));
    out->id   = mpack_node_u32(mpack_node_map_cstr(root, "id"));
    out->data = node_bindup(mpack_node_map_cstr(root, "data"), &out->data_len);

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

void command_free(Command *cmd) {
    free(cmd->data);
    memset(cmd, 0, sizeof(*cmd));
}

int pack_encode_command(const Command *cmd, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 3);
    mpack_write_cstr(&writer, "code");
    mpack_write_u32(&writer, cmd->code);
    mpack_write_cstr(&writer, "id");
    mpack_write_u32(&writer, cmd->id);
    mpack_write_cstr(&writer, "data");
    if (cmd->data)
        mpack_write_bin(&writer, (const char *)cmd->data, cmd->data_len);
    else
        mpack_write_nil(&writer);
    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_error(const char *error, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "error");
    mpack_write_cstr(&writer, error ? error : "");
    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_pwd(const char *path, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "path");
    mpack_write_cstr(&writer, path ? path : "");
    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_shell(const char *output, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "output");
    mpack_write_cstr(&writer, output ? output : "");
    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_cat(const char *path, const uint8_t *content, size_t content_len, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 2);
    mpack_write_cstr(&writer, "path");
    mpack_write_cstr(&writer, path ? path : "");
    mpack_write_cstr(&writer, "content");
    if (content)
        mpack_write_bin(&writer, (const char *)content, content_len);
    else
        mpack_write_nil(&writer);
    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_ls(bool result, const char *status, const char *path, const uint8_t *files, size_t files_len, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 4);
    mpack_write_cstr(&writer, "result");
    mpack_write_bool(&writer, result);
    mpack_write_cstr(&writer, "status");
    mpack_write_cstr(&writer, status ? status : "");
    mpack_write_cstr(&writer, "path");
    mpack_write_cstr(&writer, path ? path : "");
    mpack_write_cstr(&writer, "files");
    if (files)
        mpack_write_bin(&writer, (const char *)files, files_len);
    else
        mpack_write_nil(&writer);
    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_ps(bool result, const char *status, const uint8_t *procs, size_t procs_len, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 3);
    mpack_write_cstr(&writer, "result");
    mpack_write_bool(&writer, result);
    mpack_write_cstr(&writer, "status");
    mpack_write_cstr(&writer, status ? status : "");
    mpack_write_cstr(&writer, "processes");
    if (procs)
        mpack_write_bin(&writer, (const char *)procs, procs_len);
    else
        mpack_write_nil(&writer);
    mpack_finish_map(&writer);

    mpack_error_t err = mpack_writer_destroy(&writer);
    if (err != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_exfil_pack(uint32_t id, uint32_t type, const char *task, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 3);
    mpack_write_cstr(&writer, "id");
    mpack_write_u32(&writer, id);
    mpack_write_cstr(&writer, "type");
    mpack_write_u32(&writer, type);
    mpack_write_cstr(&writer, "task");
    mpack_write_cstr(&writer, task ? task : "");
    mpack_finish_map(&writer);

    mpack_error_t err2 = mpack_writer_destroy(&writer);
    if (err2 != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_job(uint32_t command_id, const char *job_id, const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 3);
    mpack_write_cstr(&writer, "command_id");
    mpack_write_u32(&writer, command_id);
    mpack_write_cstr(&writer, "job_id");
    mpack_write_cstr(&writer, job_id ? job_id : "");
    mpack_write_cstr(&writer, "data");
    if (data)
        mpack_write_bin(&writer, (const char *)data, data_len);
    else
        mpack_write_nil(&writer);
    mpack_finish_map(&writer);

    mpack_error_t err3 = mpack_writer_destroy(&writer);
    if (err3 != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_ans_download(int file_id, const char *path, int size_total, const uint8_t *content, size_t content_len, bool start, bool finish, bool canceled, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 7);
    mpack_write_cstr(&writer, "id");
    mpack_write_i32(&writer, file_id);
    mpack_write_cstr(&writer, "path");
    mpack_write_cstr(&writer, path ? path : "");
    mpack_write_cstr(&writer, "size");
    mpack_write_i32(&writer, size_total);
    mpack_write_cstr(&writer, "content");
    if (content)
        mpack_write_bin(&writer, (const char *)content, content_len);
    else
        mpack_write_nil(&writer);
    mpack_write_cstr(&writer, "start");
    mpack_write_bool(&writer, start);
    mpack_write_cstr(&writer, "finish");
    mpack_write_bool(&writer, finish);
    mpack_write_cstr(&writer, "canceled");
    mpack_write_bool(&writer, canceled);
    mpack_finish_map(&writer);

    mpack_error_t err4 = mpack_writer_destroy(&writer);
    if (err4 != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_ans_run(const char *stdout_str, size_t stdout_len, const char *stderr_str, size_t stderr_len, int pid, bool start, bool finish, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 5);
    mpack_write_cstr(&writer, "stdout");
    mpack_write_str(&writer, stdout_str ? stdout_str : "", stdout_str ? stdout_len : 0);
    mpack_write_cstr(&writer, "stderr");
    mpack_write_str(&writer, stderr_str ? stderr_str : "", stderr_str ? stderr_len : 0);
    mpack_write_cstr(&writer, "pid");
    mpack_write_i32(&writer, pid);
    mpack_write_cstr(&writer, "start");
    mpack_write_bool(&writer, start);
    mpack_write_cstr(&writer, "finish");
    mpack_write_bool(&writer, finish);
    mpack_finish_map(&writer);

    mpack_error_t err5 = mpack_writer_destroy(&writer);
    if (err5 != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_ans_job_list(const uint8_t *list_data, size_t list_len, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "list");
    mpack_write_bin(&writer, (const char *)list_data, (uint32_t)list_len);
    mpack_finish_map(&writer);

    mpack_error_t err6 = mpack_writer_destroy(&writer);
    if (err6 != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_term_pack(uint32_t id, int term_id, const uint8_t *key, const uint8_t *iv, bool alive, const char *status, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 6);
    mpack_write_cstr(&writer, "id");
    mpack_write_u32(&writer, id);
    mpack_write_cstr(&writer, "term_id");
    mpack_write_i32(&writer, term_id);
    mpack_write_cstr(&writer, "key");
    mpack_write_bin(&writer, (const char *)key, 16);
    mpack_write_cstr(&writer, "iv");
    mpack_write_bin(&writer, (const char *)iv, 16);
    mpack_write_cstr(&writer, "alive");
    mpack_write_bool(&writer, alive);
    mpack_write_cstr(&writer, "status");
    mpack_write_cstr(&writer, status ? status : "");
    mpack_finish_map(&writer);

    mpack_error_t err7 = mpack_writer_destroy(&writer);
    if (err7 != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}

int pack_encode_tunnel_pack(uint32_t id, uint32_t type, int channel_id, const uint8_t *key, const uint8_t *iv, bool alive, uint8_t reason, uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t size = 0;
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, &buf, &size);

    mpack_start_map(&writer, 7);
    mpack_write_cstr(&writer, "id");         mpack_write_u32(&writer, id);
    mpack_write_cstr(&writer, "type");       mpack_write_u32(&writer, type);
    mpack_write_cstr(&writer, "channel_id"); mpack_write_i32(&writer, channel_id);
    mpack_write_cstr(&writer, "key");        mpack_write_bin(&writer, (const char *)key, 16);
    mpack_write_cstr(&writer, "iv");         mpack_write_bin(&writer, (const char *)iv, 16);
    mpack_write_cstr(&writer, "alive");      mpack_write_bool(&writer, alive);
    mpack_write_cstr(&writer, "reason");     mpack_write_u8(&writer, reason);
    mpack_finish_map(&writer);

    mpack_error_t err8 = mpack_writer_destroy(&writer);
    if (err8 != mpack_ok) { free(buf); return -1; }
    *out     = (uint8_t *)buf;
    *out_len = size;
    return 0;
}
