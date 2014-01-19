#include "udp.h"

#include <stdio.h>
#include <string.h>

const int MXUDP = 1472;

uint16_t CalcCheckSum(const uint16_t* data, int len, uint32_t sum) {
    int i;
    uint32_t msk = (1 << 16) - 1;
    for (i = 0; i < len; ++i) {
        sum += ntohs(data[i]);
    }
    while (sum >> 16) {
        sum = (sum & msk) + (sum >> 16);
    }
    uint16_t res = (uint16_t) sum;
    return ~res;
}

void SetIPCheckSum(struct TIP* ip) {
    ip->CheckSum = 0;
    uint16_t checkSum = CalcCheckSum((uint16_t* ) ip, 10, 0);
    ip->CheckSum = htons(checkSum);
}

uint32_t GetPseudoHeaderSum(const struct TIP* ip) {
    uint32_t sum = 0;
    sum += ip->Protocol;
    sum += ntohs(ip->TotalLength) - 20; // length of payload
    uint16_t* data = (uint16_t* ) ip->Source;
    int i;
    for (i = 0; i < 4; ++i) {
        sum += ntohs(data[i]); // sum source and dest ip
    }
    return sum;
}

void SetUDPCheckSum(const struct TIP* ip, struct TUDP* udp) {
    udp->CheckSum = 0;
    int len = ntohs(udp->Length);
    if (len&1) {
        udp->Payload[len - 8] = 0;
        ++len;
    }
    len /= 2;
    uint16_t checkSum = CalcCheckSum((uint16_t* ) udp, len, GetPseudoHeaderSum(ip));
    if (checkSum == 0)
        checkSum = ~checkSum;
    udp->CheckSum = htons(checkSum);
}

void SetMac(struct TUDPPacket* packet, const uint8_t* source, const uint8_t* dest) {
    int i;
    for (i = 0; i < 6; ++i) {
        packet->Ethernet.Source[i] = source[i];
        packet->Ethernet.Dest[i] = dest[i];
    }
}

void InitUDPPacket(struct TUDPPacket* packet, const struct TMainConfig* mainConfig) {
    packet->IP = (struct TIP* ) &packet->Ethernet.Payload;
    packet->UDP = (struct TUDP* ) &packet->IP->Payload;

    SetMac(packet, mainConfig->SourceMac, mainConfig->DestMac);
    packet->Ethernet.Type = htons(0x0800); // IP

    struct TIP* ip = packet->IP;
    ip->VersionAndLength = 0x45; // IPv4, header 5*4 bytes
    ip->DSCPandECN = 0;
    ip->TotalLength = htons(28); // IP header + UDP header, no payload
    ip->ID = htons(0);
    ip->FlagsAndOffset = htons(0);
    ip->TTL = 64;
    ip->Protocol = 0x11; // UDP
    packet->UDP->SourcePort = htons(10000);
    packet->UDP->DestPort = htons(10001);
    packet->UDP->Length = htons(8);   // UDP header length
    SetIP(packet, mainConfig->SourceIP, mainConfig->DestIP);
    SetUDPCheckSum(packet->IP, packet->UDP);
    packet->Size = 42;  // All headers, no payload
}

void SetDataLen(struct TUDPPacket* packet, uint16_t dataLen) {
    if (dataLen > MXUDP) {
        dataLen = MXUDP;
        fprintf(stderr, "too much data");
    }
    packet->Size = 42 + dataLen;
    packet->UDP->Length = htons(8 + dataLen);
    packet->IP->TotalLength = htons(28 + dataLen);
    SetIPCheckSum(packet->IP);
    SetUDPCheckSum(packet->IP, packet->UDP);
}

void SetTTL(struct TUDPPacket* packet, uint8_t ttl) {
    packet->IP->TTL = ttl;
    SetIPCheckSum(packet->IP);
}

void SetIP(struct TUDPPacket* packet, const uint8_t* sourceIP, const uint8_t* destIP) {
    int i;
    for (i = 0; i < 4; ++i) {
        packet->IP->Source[i] = sourceIP[i];
        packet->IP->Dest[i] = destIP[i];
    }
    SetIPCheckSum(packet->IP);
    SetUDPCheckSum(packet->IP, packet->UDP);
}

void SetPort(struct TUDPPacket* packet, uint16_t sourcePort, uint16_t destPort) {
    packet->UDP->SourcePort = htons(sourcePort);
    packet->UDP->DestPort = htons(destPort);
    SetUDPCheckSum(packet->IP, packet->UDP);
}

void SetData(struct TUDPPacket* packet, const uint8_t* data, uint16_t dataLen) {
    if (dataLen > MXUDP) {
        dataLen = MXUDP;
        fprintf(stderr, "too much data");
    }
    memcpy(packet->UDP->Payload, data, dataLen);
    SetDataLen(packet, dataLen);
}

