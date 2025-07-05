#ifndef CRYPTO_H
#define CRYPTO_H

void crypto_init(const char *password);
int crypto_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, int len, unsigned char *out_mac);
int crypto_decrypt(const unsigned char *ciphertext, unsigned char *plaintext, int len, const unsigned char *mac);

#endif



