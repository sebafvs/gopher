//
// Created by seba on 10/17/26.
//

#ifndef GOPHER_CRYPT_H
#define GOPHER_CRYPT_H

#include "common.h"

int crypt_encrypt(const uint8_t *plaintext, size_t pt_len, const uint8_t *key, size_t key_len, uint8_t **out, size_t *out_len);
int crypt_decrypt(const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len, uint8_t **out, size_t *out_len);
int crypt_random (uint8_t *buf, size_t len);

#endif
