#include "pch.h"
#include "icmp.h"

USHORT ip_checksum(USHORT* buffer, int size) {
    UINT cksum = 0;
    while (size > 1) { cksum += *buffer++; size -= sizeof(USHORT); }
    if (size) cksum += *(UCHAR*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

static double nowUs() {
    static LARGE_INTEGER freq = [] { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return f; }();
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1e6 / (double)freq.QuadPart;
}

SOCKET openIcmpSocket() {
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) {
        printf("Unable to create an ICMP socket: error %d\n", WSAGetLastError());
        printf("(Run Visual Studio / the exe as Administrator.)\n");
    }
    return s;
}

double sendProbe(SOCKET s, const sockaddr_in& dest, int ttl) {
    ICMPHeader icmp;
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.code = 0;
    icmp.id = (USHORT)GetCurrentProcessId();
    icmp.seq = (USHORT)ttl;
    icmp.checksum = 0;
    icmp.checksum = ip_checksum((USHORT*)&icmp, sizeof(ICMPHeader));

    if (setsockopt(s, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
        printf("setsockopt failed with %d\n", WSAGetLastError());
        return -1;
    }
    double t = nowUs();
    if (sendto(s, (const char*)&icmp, sizeof(icmp), 0,
        (const sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
        printf("sendto failed with %d\n", WSAGetLastError());
        return -1;
    }
    return t;
}

bool resolveDest(const char* host, sockaddr_in& dest) {
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    unsigned long ip = inet_addr(host);
    if (ip != INADDR_NONE) { dest.sin_addr.s_addr = ip; return true; }

    addrinfo hints = {}, * res = NULL;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return false;
    dest.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return true;
}