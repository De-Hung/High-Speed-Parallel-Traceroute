#include "pch.h"
#include "icmp.h"

SOCKET openIcmpSocket();
double sendProbe(SOCKET s, const sockaddr_in& dest, int ttl);
bool resolveDest(const char* host, sockaddr_in& dest);

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <hostname or IP>\n", argv[0]);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup error\n");
        return 1;
    }

    sockaddr_in dest;
    if (!resolveDest(argv[1], dest)) {
        printf("Cannot resolve %s\n", argv[1]);
        return 1;
    }
    printf("Tracerouting to %s...\n", inet_ntoa(dest.sin_addr));

    SOCKET s = openIcmpSocket();
    if (s == INVALID_SOCKET) return 1;

    HopInfo hops[MAX_HOPS + 1];
    double start = nowUs();

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        hops[ttl].sendTime = sendProbe(s, dest, ttl);
        hops[ttl].probes = 1;
    }

    while ((nowUs() - start) < 2000000.0) {
        recvReply(s, hops, 100, dest.sin_addr.s_addr);
    }

    int last = MAX_HOPS;
    for (int i = 1; i <= MAX_HOPS; i++)
        if (hops[i].isDest) {
            last = i; 
            break;
        }

    for (int i = 1; i <= last; i++) {
        HopInfo& h = hops[i];

        if (!h.replied) {
            printf("%2d *\n", i);
            continue;
        }

        in_addr a; a.s_addr = h.routerIP;
        printf("%2d (%s) %.3f ms (%d)", i, inet_ntoa(a), h.rtt / 1000.0, h.probes);

        if (h.errType >= 0) printf("  other error: code %d, type %d", h.errCode, h.errType);

        printf("\n");
    }

    printf("Total execution time: %.0f ms\n", (nowUs() - start) / 1000.0);
    closesocket(s);
    WSACleanup();
    return 0;
}