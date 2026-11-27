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

double nowUs() {
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

bool recvReply(SOCKET s, HopInfo hops[], int timeoutMs, UINT destIP) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int ready = select(0, &fds, NULL, NULL, &tv);
    if (ready <= 0) return false;

    u_char buf[MAX_REPLY_SIZE];
    sockaddr_in from;
    int fl = sizeof(from);
    int got = recvfrom(s, (char*)buf, MAX_REPLY_SIZE, 0, (sockaddr*)&from, &fl);
    double tRecv = nowUs();

    if (got == SOCKET_ERROR || got < IP_HDR_SIZE + ICMP_HDR_SIZE) return true;

    IPHeader* outerIP = (IPHeader*)buf;
    int outerLen = outerIP->h_len * 4;
    if (got < outerLen + ICMP_HDR_SIZE) return true;
    ICMPHeader* icmp = (ICMPHeader*)(buf + outerLen);

    int seq = -1;
    if (icmp->type == ICMP_ECHO_REPLY) {
        if (icmp->id != (USHORT)GetCurrentProcessId()) return true;
        seq = icmp->seq;
    } else {
        // error message
        if (got < outerLen + ICMP_HDR_SIZE + IP_HDR_SIZE + ICMP_HDR_SIZE) return true;

        IPHeader* origIP = (IPHeader*)(buf + outerLen + ICMP_HDR_SIZE);

        int origLen = origIP->h_len * 4;
        if (got < outerLen + ICMP_HDR_SIZE + origLen + ICMP_HDR_SIZE) return true;
        if (origIP->proto != IPPROTO_ICMP) return true;

        ICMPHeader* origICMP = (ICMPHeader*)((u_char*)origIP + origLen);

        if (origICMP->id != (USHORT)GetCurrentProcessId()) return true;
        seq = origICMP->seq;
    }

    if (seq < 1 || seq > MAX_HOPS) return true;

    HopInfo& h = hops[seq];

    if (h.replied) return true; // ignore duplicates

    h.replied = true;
    h.routerIP = outerIP->source_ip;
    h.rtt = tRecv - h.sendTime;

    if (icmp->type == ICMP_ECHO_REPLY) h.isDest = true;
    else if (icmp->type != ICMP_TTL_EXPIRED) {
        h.errType = icmp->type;
        h.errCode = icmp->code;
    }
    return true;
}