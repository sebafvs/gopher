//
// Created by seba on 10/17/26.
//

#include "crypt.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   16

int crypt_encrypt(const uint8_t *plaintext, size_t pt_len, const uint8_t *key, size_t key_len, uint8_t **out, size_t *out_len) {

    // output = nonce (12) + ciphertext (pt_len) + tag (16)
    size_t total = GCM_NONCE_LEN + pt_len + GCM_TAG_LEN;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    // generate random nonce
    if (RAND_bytes(buf, GCM_NONCE_LEN) != 1) {
        free(buf);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(buf); return -1; }

    const EVP_CIPHER *cipher = (key_len == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();

    int ok = 0; int len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, buf) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, buf + GCM_NONCE_LEN, &len, plaintext, (int)pt_len) != 1) goto done;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, buf + GCM_NONCE_LEN + len, &final_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, buf + GCM_NONCE_LEN + len + final_len) != 1) goto done;

    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(buf); return -1; }

    *out     = buf;
    *out_len = total;
    return (int)total;
}

int crypt_decrypt(const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len, uint8_t **out, size_t *out_len) {

    if (data_len < GCM_NONCE_LEN + GCM_TAG_LEN) return -1;

    const uint8_t *nonce      = data;
    const uint8_t *ciphertext = data + GCM_NONCE_LEN;
    size_t ct_len = data_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    const uint8_t *tag = data + GCM_NONCE_LEN + ct_len;

    uint8_t *plaintext = malloc(ct_len > 0 ? ct_len : 1);
    if (!plaintext) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(plaintext); return -1; }

    const EVP_CIPHER *cipher = (key_len == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();

    int ok = 0;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, nonce) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ct_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag) != 1) goto done;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1) goto done;

    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(plaintext); return -1; }

    *out     = plaintext;
    *out_len = ct_len;
    return (int)ct_len;
}

int crypt_random(uint8_t *buf, size_t len) {
    return (RAND_bytes(buf, (int)len) == 1) ? 0 : -1;
}
