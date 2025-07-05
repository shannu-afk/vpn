#include "crypto.h"
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <string.h>

static unsigned char aes_key[32];  // 256-bit key
static unsigned char hmac_key[32]; // HMAC key

void crypto_init(const char *password) {
    size_t len = strlen(password);
    for (int i = 0; i < 32; ++i) {
        aes_key[i] = password[i % len];
        hmac_key[i] = password[(i + 8) % len];
    }
}

int crypto_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char *out_mac) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, 256);

    unsigned char iv[16] = {0};

    // Add PKCS7 padding
    int padded_len = ((len / 16) + 1) * 16;
    unsigned char padded[1024] = {0};
    memcpy(padded, plaintext, len);
    int pad_val = padded_len - len;
    for (int i = 0; i < pad_val; i++) {
        padded[len + i] = pad_val;
    }

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded, ciphertext);
    mbedtls_aes_free(&aes);

    // HMAC-SHA256
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, hmac_key, 32);
    mbedtls_md_hmac_update(&ctx, ciphertext, padded_len);
    mbedtls_md_hmac_finish(&ctx, out_mac);
    mbedtls_md_free(&ctx);

    return padded_len;
}

int crypto_decrypt(const unsigned char *ciphertext, unsigned char *plaintext, int len, const unsigned char *mac) {
    unsigned char computed_mac[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, hmac_key, 32);
    mbedtls_md_hmac_update(&ctx, ciphertext, len);
    mbedtls_md_hmac_finish(&ctx, computed_mac);
    mbedtls_md_free(&ctx);

    if (memcmp(mac, computed_mac, 32) != 0) {
        return -1;  // HMAC mismatch
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aes_key, 256);

    unsigned char iv[16] = {0};
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, ciphertext, plaintext);
    mbedtls_aes_free(&aes);

    // Remove PKCS7 padding
    int pad_val = plaintext[len - 1];
    if (pad_val <= 0 || pad_val > 16) {
        return -1;
    }

    return len - pad_val;
}
