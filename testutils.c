#include "testutils.h"
#include "udp.h"
#include "structures.h"
#include "ts_util.h"
#include "macroses.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

pcap_t* pcap;
pcap_dumper_t* dumper;
int offline;
struct timespec starttime;
struct timespec timenow;
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
const int32_t magic = 0x64ab83cd;

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

