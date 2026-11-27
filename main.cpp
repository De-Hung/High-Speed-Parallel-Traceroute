#include "pch.h"
#include "icmp.h"

SOCKET openIcmpSocket();
double sendProbe(SOCKET s, const sockaddr_in& dest, int ttl);
bool resolveDest(const char* host, sockaddr_in& dest);

int main(int argc, char** argv) {
    if (argc != 2) { printf("Usage: %s <hostname or IP>\n", argv[0]); return 1; }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSAStartup error\n"); return 1; }

    sockaddr_in dest;
    if (!resolveDest(argv[1], dest)) { printf("Cannot resolve %s\n", argv[1]); return 1; }
    printf("Tracerouting to %s...\n", inet_ntoa(dest.sin_addr));

    SOCKET s = openIcmpSocket();
    if (s == INVALID_SOCKET) return 1;

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++)
        sendProbe(s, dest, ttl);

    printf("Sent %d probes.\n", MAX_HOPS);
    closesocket(s);
    WSACleanup();
    return 0;
}