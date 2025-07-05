#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"

#include "crypto.h"
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>

int main() {
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    const char *pers = "tls_client";

    char *server_ip = "127.0.0.1";
    char *server_port = "1194";

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *) pers, strlen(pers));

    // Load server certificate (optional, for validation)
    // mbedtls_x509_crt_parse_file(&cacert, "certs/server.crt");

    mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // No cert verification
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_setup(&ssl, &conf);

    mbedtls_ssl_set_hostname(&ssl, "localhost");

    mbedtls_net_connect(&server_fd, server_ip, server_port, MBEDTLS_NET_PROTO_TCP);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // Perform TLS handshake
    if (mbedtls_ssl_handshake(&ssl) != 0) {
        printf("[-] TLS handshake failed\n");
        goto exit;
    }

    printf("[+] TLS Handshake successful\n");

    const char *auth = "user:pass";
    mbedtls_ssl_write(&ssl, (const unsigned char *)auth, strlen(auth));

    char buf[1024] = {0};
    int len = mbedtls_ssl_read(&ssl, (unsigned char *)buf, sizeof(buf)-1);
    if (len <= 0 || strncmp(buf, "OK", 2) != 0) {
        printf("[ERROR] Authentication failed\n");
        goto exit;
    }

    printf("[+] Auth successful. You can now send messages.\n");
    crypto_init("secret123");

    while (1) {
        char input[512];
        printf("You: ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        unsigned char encrypted[1024];
        unsigned char hmac[32];
        int enc_len = crypto_encrypt((unsigned char *)input, encrypted, strlen(input), hmac);
        memcpy(encrypted + enc_len, hmac, 32);

        mbedtls_ssl_write(&ssl, encrypted, enc_len + 32);

        unsigned char reply[1056];
        int reply_len = mbedtls_ssl_read(&ssl, reply, sizeof(reply));
        if (reply_len <= 32) break;

        unsigned char dec[1024];
        memcpy(hmac, reply + (reply_len - 32), 32);
        int dec_len = crypto_decrypt(reply, dec, reply_len - 32, hmac);
        dec[dec_len] = '\0';

        printf("Server: %s\n", dec);
    }

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);
    return 0;
}
