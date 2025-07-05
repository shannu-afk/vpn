#include "auth.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

int authenticate(int sock, const char *username, const char *password) {
    char msg[256];
    snprintf(msg, sizeof(msg), "%s:%s", username, password);
    printf("[DEBUG] Sending auth: %s\n", msg);
    send(sock, msg, strlen(msg), 0);

    char resp[64] = {0};
    recv(sock, resp, sizeof(resp), 0);

    return (strcmp(resp, "OK") == 0) ? 0 : -1;
}
