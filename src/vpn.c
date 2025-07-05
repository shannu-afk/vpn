#include "vpn.h"
#include "network.h"
#include "auth.h"
#include "crypto.h"
#include "log.h"
#include <stdio.h>
#include <string.h>

int vpn_init() {
    const char *ip = "127.0.0.1";
    int port = 1194;
    const char *username = "user";
    const char *password = "pass";
    const char *crypto_pass = "secret123";

    // 1. Connect
    int sockfd = network_connect(ip, port);
    if (sockfd < 0) {
        log_error("Connection failed");
        return -1;
    }

    // 2. Send credentials BEFORE encryption starts
    if (authenticate(sockfd, username, password) < 0) {
        log_error("Authentication failed");
        network_close(sockfd);
        return -1;
    }

    // 3. Now initialize crypto with shared password
    crypto_init(crypto_pass);

    // 4. Send encrypted message
    unsigned char msg[] = "Hello Server!";
    unsigned char encrypted[1024];
    unsigned char hmac[32];

    int enc_len = crypto_encrypt(msg, encrypted, strlen((char *)msg), hmac);
    memcpy(encrypted + enc_len, hmac, 32);
    network_send(sockfd, (char *)encrypted, enc_len + 32);
    log_info("Encrypted message sent");

    // 5. Receive and decrypt server reply
    unsigned char response[1056];
    int recv_len = network_recv(sockfd, (char *)response, sizeof(response));
    if (recv_len > 32) {
        unsigned char decrypted[1024];
        int plain_len = crypto_decrypt(response, decrypted, recv_len - 32, response + recv_len - 32);
        if (plain_len > 0) {
            decrypted[plain_len] = '\0';
            printf("Server replied: %s\n", decrypted);
        } else {
            log_error("Decryption failed or HMAC mismatch");
        }
    }

    network_close(sockfd);
    return 0;
}
