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

int InitWriter(const char* name) {
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

uint32_t PacketsPerTest;
int CurrentTest;
uint32_t Recived;
int HasFirst;
double SumLen;
double SumPayload;
double FirstTime;
double LastTime;
const char ColumnTest[] = "Test";
const char ColumnRecived[] = "Recived";
const char ColumnRecivedPercent[] = "Recived %";
const char ColumnAvgSize[] = "AVG size";
const char ColumnAvgPayload[] = "AVG payload";
const char ColumnTime[] = "Time";
const char ColumnSpeed[] = "Speed Mbit/sec";
const char ColumnPayloadSpeed[] = "Payload speed Mbit/sec";
const char ColumnPPS[] = "Packets per sec";
const char ColumnSended[] = "Sended";
const char ColumnNetworks[] = "Networks";
const char ColumnBadPackets[] = "Bad packets %";

int InitReader(const char* name) {
    CurrentTest = 0;
    clock_gettime(CLOCK_REALTIME, &starttime);
    timenow = starttime;
    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    pcap_errbuff[0] = 0;
    if (name[0] == '-' && name[1] == 0) {
        offline = 1;
        pcap = pcap_open_offline(name, pcap_errbuff);
    } else {
        offline = 0;
        pcap = pcap_open_live(name, BUFSIZ, 0, 0, pcap_errbuff);
    }
    if (pcap_errbuff[0]) {
        fprintf(stderr, "%s\n", pcap_errbuff);
    }
    if (!pcap)
        return 1;
    return 0;
}

int32_t GetTestNum(int32_t packetNum) {
    return packetNum / PacketsPerTest;
}

void Reset(int32_t packetNum) {
    CurrentTest = GetTestNum(packetNum);
    Recived = 0;
    HasFirst = 0;
    SumLen = 0;
    SumPayload = 0;
}

double GetTestTime() {
    return LastTime - FirstTime;
}

void PrintStat(int update) {
    if (update)
        printf("\r");
    else
        printf("\n");
    printf("%4d %8d %10.2lf ", CurrentTest, Recived, Recived*100.0/PacketsPerTest);
    if (Recived == 0)
        Recived = 1;
    double tm = GetTestTime();
    printf("%9.2lf %12.2lf %10.4lf ", SumLen/Recived, SumPayload/Recived, tm);
    if (tm < 1e-9)
        tm = 1e-9;
    const int MBITDIV = (1<<20)/8;
    printf("%15.2lf %23.2lf %16.2lf", SumLen/tm/MBITDIV, SumPayload/tm/MBITDIV, Recived/tm);
    if (!update)
        fflush(stdout);
}

void ReaderCallback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (pkthdr->len < 50)
        return;
    struct TEthernet* eth = (struct TEthernet*) packet;
    struct TIP* ip = (struct TIP*) eth->Payload;
    struct TUDP* udp = (struct TUDP*) ip->Payload;
    int32_t packetNum = ReadPacketNum(udp->Payload);
    if (packetNum == -1)
        return;
    if (GetTestNum(packetNum) > CurrentTest) {
        PrintStat(0);
        Reset(packetNum);
    }

    int headerLen = udp->Payload - packet;
    SumLen += pkthdr->len;
    SumPayload += pkthdr->len - headerLen;
    ++Recived;
    if (!HasFirst) {
        FirstTime = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec/1e6;
        HasFirst = 1;
    }
    LastTime = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec/1e6;

    if (GetTestNum(packetNum + 1) > CurrentTest) {
        PrintStat(0);
        Reset(packetNum + 1);
    }
    fflush(stdout);
}

int ReadPackets(const struct TConfig* config) {
    PacketsPerTest = config->MainConfig.PacketsPerTest;
    if (InitReader(config->MainConfig.Device))
        return 1;
    printf("%4s %8s %10s ", ColumnTest, ColumnRecived, ColumnRecivedPercent);
    printf("%9s %12s %10s ", ColumnAvgSize, ColumnAvgPayload, ColumnTime);
    printf("%15s %23s %16s", ColumnSpeed, ColumnPayloadSpeed, ColumnPPS);
    fflush(stdout);
    pcap_loop(pcap, -1, ReaderCallback, NULL);
    puts("");
}

int FinishWriter() {
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

void WriteIntToBytes(char* dest, int32_t val) {
    int i;
    for (i = 0; i < 4; ++i) {
        dest[i] = val & 255;
        val >>= 8;
    }
}

const int32_t magic = 0x64ab83cd;

void WritePacketNum(char* dest, int32_t packetNum) {
    WriteIntToBytes(dest, magic);
    WriteIntToBytes(dest + 4, packetNum);
}

int32_t ReadIntFromBytes(uint8_t* src) {
    int i;
    uint32_t res = 0;
    for (i = 3; i >= 0; --i) {
        res <<= 8;
        res |= src[i];
    }
    return res;
}

int32_t ReadPacketNum(char* src) {
    if (ReadIntFromBytes(src) != magic)
        return -1;
    return ReadIntFromBytes(src + 4);
}

void WriteReversed(char* dest, int32_t data, int cnt) {
    int i;
    for (i = 0; i < cnt; ++i) {
        dest[i] = ReverseBits((uint8_t)(data & 255));
        data >>= 8;
    }
}

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
            SendPacket(&packet, tv);
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
    InitUDPPacket(&packet);
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
            SendPacket(&packet, tv);
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
    InitUDPPacket(&packet);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
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
            SendPacket(&packet, tv);
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
    InitUDPPacket(&packet);
    uint8_t payload[18];
    memset(payload, 'x', sizeof(payload));
    struct timeval tv;
    tv.tv_sec = 0;
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
                SetMac(&packet, SourceMac, DestMac);
                ++badPackets;
            } else {
                SetMac(&packet, SourceMac, FakeDestMac);
            }
            SendPacket(&packet, tv);
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

int TestsCount = ARRAY_SIZE(Tests);

char TestNames[][32] = {
    "many_networks",
    "different_payload",
    "low_ttl",
    "bad_mac"
};
