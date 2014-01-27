#include "tests.h"
#include "udp.h"
#include "structures.h"
#include "ts_util.h"
#include "macroses.h"
#include "testutils.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>


int ManyNetworksTest(const struct TConfig* config) {
    if (InitWriter(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    int start = config->ManyNetworkConfig.Start;
    int step = config->ManyNetworkConfig.Step;
    int tests = config->ManyNetworkConfig.TestsCount;
    int testNum;
    uint32_t networkCount = start;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet, &config->MainConfig);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    uint8_t sourceIP[4];
    uint8_t destIP[4];
    sourceIP[0] = 200;
    destIP[0] = 201;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    fprintf(stderr, "Many networks test\n%4s %8s %10s\n", ColumnTest, ColumnSended, ColumnNetworks);
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
            SendPacket(&packet, &tv, config->MainConfig.Delay);
            ++packetNum;
        }
        fprintf(stderr, "%4d %8d %10d\n", testNum, packetsPerTest, networkCount);
    }
    FinishWriter();
}

int DifferentPayloadSizeTest(const struct TConfig* config) {
    if (InitWriter(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    int start = config->DifferentPayloadConfig.Start;
    int step = config->DifferentPayloadConfig.Step;
    int tests = config->DifferentPayloadConfig.TestsCount;
    int testNum;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet, &config->MainConfig);
    uint8_t payload[MXUDP];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    fprintf(stderr, "Different payload test\n%4s %8s %10s %12s\n", ColumnTest, ColumnSended, ColumnAvgSize, ColumnAvgPayload);
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
            SendPacket(&packet, &tv, config->MainConfig.Delay);
            ++packetNum;
        }
        fprintf(stderr, "%4d %8d %10d %12d\n", testNum, packetsPerTest, packet.Size, size);
    }
    FinishWriter();
}

int LowTTLTest(const struct TConfig* config) {
    if (InitWriter(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    double start = config->LowTTLConfig.Start;
    double step = config->LowTTLConfig.Step;
    int tests = config->LowTTLConfig.TestsCount;
    int testNum;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet, &config->MainConfig);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    fprintf(stderr, "Low TTL test\n%4s %8s %15s\n", ColumnTest, ColumnSended, ColumnBadPackets);
    for (testNum = 0; testNum < tests; ++testNum) {
        double frenq = start + testNum*step;
        if (frenq < 0)
            frenq = 0;
        if (frenq > 1)
            frenq = 1;
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
            SendPacket(&packet, &tv, config->MainConfig.Delay);
            packetNum++;
        }
        fprintf(stderr, "%4d %8d %15.2lf\n", testNum, packetsPerTest, frenq*100);
    }
    FinishWriter();
}

int BadMacTest(const struct TConfig* config) {
    if (InitWriter(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    double start = config->BadMacConfig.Start;
    double step = config->BadMacConfig.Step;
    int tests = config->BadMacConfig.TestsCount;
    int testNum;
    uint32_t packetNum = 0;
    struct TUDPPacket packet;
    InitUDPPacket(&packet, &config->MainConfig);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    fprintf(stderr, "Bad MAC test\n%4s %8s %15s\n", ColumnTest, ColumnSended, ColumnBadPackets);
    for (testNum = 0; testNum < tests; ++testNum) {
        double frenq = start + testNum*step;
        if (frenq < 0)
            frenq = 0;
        if (frenq > 1)
            frenq = 1;
        int badPackets = 0;
        int i;
        for (i = 0; i < packetsPerTest; ++i) {
            WritePacketNum(payload, packetNum);
            SetData(&packet, payload, sizeof(payload));
            if (i != 0 && i != packetsPerTest - 1 && badPackets < i*frenq) {
                SetMac(&packet, config->MainConfig.SourceMac, config->MainConfig.FakeDestMac);
                ++badPackets;
            } else {
                SetMac(&packet, config->MainConfig.SourceMac, config->MainConfig.DestMac);
            }
            SendPacket(&packet, &tv, config->MainConfig.Delay);
            packetNum++;
        }
        fprintf(stderr, "%4d %8d %15.2lf\n", testNum, packetsPerTest, frenq*100);
    }
    FinishWriter();
}

TTestFuncPointer Tests[] = {
    &ManyNetworksTest,
    &DifferentPayloadSizeTest,
    &LowTTLTest,
    &BadMacTest
};

const int TestsCount = ARRAY_SIZE(Tests);

const char TestNames[][32] = {
    "many_networks",
    "different_payload",
    "low_ttl",
    "bad_mac"
};
