#include "tests.h"
#include "udp.h"
#include "structures.h"
#include "ts_util.h"
#include "macroses.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>

pcap_t* pcap;
pcap_dumper_t* dumper;
int offline;
struct timespec starttime;
struct timespec timenow;

void WaitFor(struct timeval ts) {
    struct timespec sendtime;
    TimevalToTimespec(&ts, &sendtime);
    sendtime = TsAdd(sendtime, starttime);
    if (TsCompare(sendtime,timenow) <= 0)
        return;
    clock_gettime(CLOCK_REALTIME, &timenow);
    if (TsCompare(sendtime, timenow) <= 0)
        return;
    struct timespec waittime;
    waittime = TsSubtract(sendtime, timenow);
    if (nanosleep(&waittime, NULL)) {
        fprintf(stderr, "nanosleep error\n");
    }
}

int SendPacket(struct TUDPPacket* packet, struct timeval ts) {
    if (offline) {
        struct pcap_pkthdr header;
        header.ts = ts;
        header.caplen = packet->Size;
        header.len = packet->Size;
        pcap_dump((u_char* ) dumper, &header, (u_char *) &packet->Ethernet);
    } else {
        WaitFor(ts);
        if (pcap_inject(pcap, (u_char *) &packet->Ethernet, packet->Size) == -1) {
            pcap_perror(pcap, 0);
            pcap_close(pcap);
            return 1;
        }
    }
    return 0;
}

int Init(const char* name) {
    clock_gettime(CLOCK_REALTIME, &starttime);
    timenow = starttime;
    if (name[0] == '-' && name[1] == 0) {
        offline = 1;
        pcap = pcap_open_dead(DLT_EN10MB, 65535);
        dumper = pcap_dump_open(pcap, name);
    } else {
        offline = 0;
        if (strcmp(name, "default") == 0) {
            char* dev;
            int res = GetDefaultDevice(&dev);
            if (res)
                return res;
            fprintf(stderr, "Using default device: %s\n", dev);
            name = dev;
        }
        char pcap_errbuff[PCAP_ERRBUF_SIZE];
        pcap_errbuff[0] = 0;
        pcap =  pcap_open_live(name, BUFSIZ, 0, 0, pcap_errbuff);
        if (pcap_errbuff[0]) {
            fprintf(stderr, "%s\n", pcap_errbuff);
        }
        if (!pcap)
            return 1;
    }
    return 0;
}

int Finish() {
    if (offline) {
        pcap_dump_close(dumper);
        pcap_close(pcap);
    } else {
        pcap_close(pcap);
    }
}


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

int ManyNetworksTest(const struct TConfig* config) {
    if (Init(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    int start = config->ManyNetworkConfig.Start;
    int step = config->ManyNetworkConfig.Step;
    int tests = config->ManyNetworkConfig.TestsCount;
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

int DifferentPayloadSizeTest(const struct TConfig* config) {
    if (Init(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    int start = config->DifferentPayloadConfig.Start;
    int step = config->DifferentPayloadConfig.Step;
    int tests = config->DifferentPayloadConfig.TestsCount;
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

int LowTTLTest(const struct TConfig* config) {
    if (Init(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    double start = config->LowTTLConfig.Start;
    double step = config->LowTTLConfig.Step;
    int tests = config->LowTTLConfig.TestsCount;
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

int BadMacTest(const struct TConfig* config) {
    if (Init(config->MainConfig.Device))
        return 1;
    int packetsPerTest = config->MainConfig.PacketsPerTest;
    double start = config->BadMacConfig.Start;
    double step = config->BadMacConfig.Step;
    int tests = config->BadMacConfig.TestsCount;
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

TTestFuncPointer Tests[] = {
    &ManyNetworksTest,
    &DifferentPayloadSizeTest,
    &LowTTLTest,
    &BadMacTest
};

int TestsCount = ARRAY_SIZE(Tests);

char TestNames[][32] = {
    "many_networks",
    "different_payload",
    "low_ttl",
    "bad_mac"
};
