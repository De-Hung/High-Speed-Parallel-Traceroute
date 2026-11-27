#pragma once
#include "pch.h"

#define IP_HDR_SIZE      20
#define ICMP_HDR_SIZE    8
#define MAX_REPLY_SIZE   512
#define MAX_HOPS         30

#define ICMP_ECHO_REPLY   0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRED  11
#define ICMP_ECHO_REQUEST 8

#pragma pack(push, 1)

struct IPHeader {
    UCHAR  h_len : 4;
    UCHAR  version : 4;
    UCHAR  tos;
    USHORT len;
    USHORT ident;
    USHORT flags;
    UCHAR  ttl;
    UCHAR  proto;
    USHORT checksum;
    UINT   source_ip;
    UINT   dest_ip;
};

struct ICMPHeader {
    UCHAR  type;
    UCHAR  code;
    USHORT checksum;
    USHORT id;
    USHORT seq;
};

#pragma pack(pop)

USHORT ip_checksum(USHORT* buffer, int size);
struct HopInfo {
    double sendTime = 0;
    double rtt = -1;
    UINT   routerIP = 0;
    int    probes = 0;
    bool   replied = false;
    bool   isDest = false;
    int    errType = -1;
    int    errCode = -1;
};

double nowUs(); // timer visible to main
bool recvReply(SOCKET s, HopInfo hops[], int timeoutMs, UINT destIP);