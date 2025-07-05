#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/debug.h>

#include "crypto.h"  // Your custom encryption logic
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef struct {
    SOCKET client_fd;
    char password[128];
} client_args;

// Optional debug function
void mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) {
    ((void) level);
    fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
}

int tls_handshake(mbedtls_ssl_context *ssl) {
    int ret;
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char errbuf[100];
            mbedtls_strerror(ret, errbuf, 100);
            printf("Handshake failed: %s\n", errbuf);
            return -1;
        }
    }
    return 0;
}

unsigned __stdcall handle_client(void *args_ptr) {
    client_args *args = (client_args *)args_ptr;
    SOCKET client_fd = args->client_fd;
    char password[128];
    strcpy(password, args->password);
    free(args_ptr);

    mbedtls_net_context client_ctx;
    mbedtls_net_init(&client_ctx);
    client_ctx.fd = client_fd;

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "vpn_server";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    mbedtls_x509_crt_parse_file(&cert, "certs/server.crt");
    mbedtls_pk_parse_keyfile(&key, "certs/server.key", NULL);

    mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&conf, cert.next, NULL);
    mbedtls_ssl_conf_own_cert(&conf, &cert, &key);

    // Force TLS 1.2
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    // Optional debugging
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg(&conf, mbedtls_debug, stdout);

    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, &client_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    if (tls_handshake(&ssl) != 0) {
        printf("TLS handshake failed\n");
        goto cleanup;
    }

    unsigned char buffer[1056];
    unsigned char decrypted[1024];
    unsigned char reply[1056];
    unsigned char hmac[32];

    int recv_len = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer) - 1);
    if (recv_len <= 0) goto cleanup;
    buffer[recv_len] = '\0';
    printf("Received auth: %s\n", buffer);

    if (strcmp((char *)buffer, "user:pass") != 0) {
        printf("[ERROR] Authentication failed\n");
        mbedtls_ssl_write(&ssl, (const unsigned char *)"FAIL", 4);
        goto cleanup;
    }

    mbedtls_ssl_write(&ssl, (const unsigned char *)"OK", 2);
    crypto_init(password);  // Initialize your encryption

    while ((recv_len = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer))) > 32) {
        int cipher_len = recv_len - 32;
        memcpy(hmac, buffer + cipher_len, 32);

        int dec_len = crypto_decrypt(buffer, decrypted, cipher_len, hmac);
        if (dec_len <= 0) {
            printf("[ERROR] HMAC mismatch or decrypt failed.\n");
            break;
        }

        decrypted[dec_len] = '\0';
        printf("Client: %s\n", decrypted);

        int reply_len = crypto_encrypt(decrypted, reply, dec_len, hmac);
        memcpy(reply + reply_len, hmac, 32);
        mbedtls_ssl_write(&ssl, reply, reply_len + 32);
    }

cleanup:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&client_ctx);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    closesocket(client_fd);
    return 0;
}

int main() {
    WSADATA wsa;
    SOCKET server_fd;
    struct sockaddr_in server, client;
    int c;

    printf("Secure VPN Server (TLS enabled) running on 127.0.0.1:1194\n");

    char password[128];
    printf("Enter VPN password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    WSAStartup(MAKEWORD(2, 2), &wsa);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(1194);
    bind(server_fd, (struct sockaddr *)&server, sizeof(server));
    listen(server_fd, 5);

    printf("Waiting for TLS clients...\n");
    while (1) {
        c = sizeof(struct sockaddr_in);
        SOCKET client_fd = accept(server_fd, (struct sockaddr *)&client, &c);
        if (client_fd == INVALID_SOCKET) continue;

        printf("Client connected.\n");

        client_args *args = (client_args *)malloc(sizeof(client_args));
        args->client_fd = client_fd;
        strcpy(args->password, password);
        _beginthreadex(NULL, 0, handle_client, args, 0, NULL);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
