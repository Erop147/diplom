#include "tests.h"
#include "udp.h"
#include "structures.h"
#include "ts_util.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>

uint8_t ReverseBits(uint8_t x) {
    uint8_t res = 0;
    int i = 0;
    for (i = 0; i < 8; ++i) {
        if (x & (1 << i))
            res |= 1 << (7 - i);
    }
    return res;
}

void WritePacketNum(char* dest, uint32_t packetNum) {
    int i;
    for (i = 0; i < 4; ++i) {
        dest[i] = packetNum & 255;
        packetNum >>= 8;
    }
}

void WriteReversed(char* dest, uint32_t data, int cnt) {
    int i;
    for (i = 0; i < cnt; ++i) {
        dest[i] = ReverseBits((uint8_t)(data & 255));
        data >>= 8;
    }
}

int ManyNetworksTest() {
    Init("-");
    int packetsPerTest = 10;
    int start = 1;
    int step = 3;
    int tests = 10;
    int testNum;
    uint32_t networkCount = start;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    uint8_t sourceIP[4];
    uint8_t destIP[4];
    sourceIP[0] = 200;
    destIP[0] = 201;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    for (testNum = 0; testNum < tests; ++testNum) {
        networkCount = start + step*testNum;
        if (networkCount == 0)
            networkCount = 1;
        int i;
        for (i = 0; i < packetsPerTest; ++i) {
            WritePacketNum(payload, packetNum);
            WriteReversed(sourceIP + 1, i % networkCount, 3);
            WriteReversed(destIP + 1, i % networkCount, 3);
            SetIP(&packet, sourceIP, destIP);
            SetData(&packet, payload, sizeof(payload));
            SendPacket(&packet, tv);
            ++packetNum;
        }
    }
    Finish();
}

void DifferentPayloadSizeTest() {
    Init("-");
    int packetsPerTest = 10;
    int start = 18;
    int step = 1;
    int tests = MXUDP - start + 1;
    int testNum;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet);
    uint8_t payload[MXUDP];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    for (testNum = 0; testNum < tests; ++testNum) {
        int size = start + testNum*step;
        if (size < 18)
            size = 18;
        if (size > MXUDP)
            size = MXUDP;
        int i;
        for (i = 0; i < packetsPerTest; ++i) {
            WritePacketNum(payload, packetNum);
            SetData(&packet, payload, size);
            SendPacket(&packet, tv);
            ++packetNum;
        }
    }
    Finish();
}

void LowTTLTest() {
    Init("-");
    int packetsPerTest = 10;
    double start = 0;
    double step = 0.1;
    int tests = 10;
    int testNum;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
    for (testNum = 0; testNum < tests; ++testNum) {
        double frenq = start + testNum*step;
        int badPackets = 0;
        int i;
        for (i = 0; i < packetsPerTest; ++i) {
            WritePacketNum(payload, packetNum);
            SetData(&packet, payload, sizeof(payload));
            if (i != 0 && i != packetsPerTest - 1 && badPackets < i*frenq) {
                SetTTL(&packet, 1);
                ++badPackets;
            } else {
                SetTTL(&packet, 64);
            }
            SendPacket(&packet, tv);
        }
    }
    Finish();
}

void BadMacTest() {
    Init("-");
    int packetsPerTest = 10;
    double start = 0;
    double step = 0.1;
    int tests = 10;
    int testNum;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
    for (testNum = 0; testNum < tests; ++testNum) {
        double frenq = start + testNum*step;
        int badPackets = 0;
        int i;
        for (i = 0; i < packetsPerTest; ++i) {
            WritePacketNum(payload, packetNum);
            SetData(&packet, payload, sizeof(payload));
            if (i != 0 && i != packetsPerTest - 1 && badPackets < i*frenq) {
                SetMac(&packet, SourceMac, DestMac);
                ++badPackets;
            } else {
                SetMac(&packet, SourceMac, FakeDestMac);
            }
            SendPacket(&packet, tv);
        }
    }
    Finish();
}


