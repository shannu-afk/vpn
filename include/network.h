#ifndef NETWORK_H
#define NETWORK_H

int network_connect(const char *ip, int port);
void network_send(int sock, const char *data, int len);
int network_recv(int sock, char *buf, int len);
void network_close(int sock);

#endif