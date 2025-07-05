#include "network.h"
#include <winsock2.h>

int network_connect(const char *ip, int port) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;

    WSAStartup(MAKEWORD(2,2), &wsa);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        return -1;
    }

    return sock;
}

void network_send(int sock, const char *data, int len) {
    send(sock, data, len, 0);
}

int network_recv(int sock, char *buf, int len) {
    return recv(sock, buf, len, 0);
}

void network_close(int sock) {
    closesocket(sock);
    WSACleanup();
}
