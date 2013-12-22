#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>

#include "structures.h"

int GetDefaultDevice(char** res) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\nMay be is it need to be root?\n", errbuf);
        return 1;
    }
    *res = dev;
    return 0;
}

int PrintDefaultDevice() {
    char* dev;
    int res = GetDefaultDevice(&dev);
    if (res)
        return res;
    printf("Default device:\n%s\n\n", dev);
    return 0;
}

int PrintAllDevices() {
    int err = PrintDefaultDevice();
    if (err)
        return err;

    struct pcap_if* found_devices;
    int result;
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = 0;
    result = pcap_findalldevs(&found_devices, errbuf);
    if (result < 0) {
        fprintf(stderr, "Device scan error:\n%s\n", errbuf);
        return 1;
    }
    if (errbuf[0]) {
        fprintf(stderr, "Device scan warning:\n%s\n", errbuf);
    }

    printf("All devices:\n");
    struct pcap_if* iter = found_devices;
    while (iter != NULL) {
        printf("%s\n", iter->name);
        iter = iter->next;
    }
    pcap_freealldevs(found_devices);
    return 0;
}

void PrintHelp(char* progName) {
    fprintf(stderr,
        "USAGE: %s [-lh]\n"
        "\n"
        "-l    print list of suitable devices. Must be root\n"
        "-h    print this help\n"
        , progName
    );
}

uint8_t SourceMac[6] = {0x00, 0x1d, 0x72, 0xca, 0x0a, 0x49};
uint8_t DestMac[6] = {0x00, 0x1d, 0x72, 0xca, 0x0a, 0x4a};
uint8_t SourceIP[4] = {192, 168, 0, 1};
uint8_t DestIP[4] = {192, 168, 1, 1};

uint16_t CalcCheckSum(uint16_t* data, int len, uint32_t sum) {
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

uint32_t GetPseudoHeaderSum(struct TIP* ip) {
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

void SetUDPCheckSum(struct TIP* ip, struct TUDP* udp) {
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

void InitUDPPacket(struct TUDPPacket* packet) {
    packet->IP = (struct TIP* ) &packet->Ethernet.Payload;
    packet->UDP = (struct TUDP* ) &packet->IP->Payload;

    int i;
    for (i = 0; i < 6; ++i) {
        packet->Ethernet.Source[i] = SourceMac[i];
        packet->Ethernet.Dest[i] = DestMac[i];
    }
    packet->Ethernet.Type = htons(0x0800); // IP

    struct TIP* ip = packet->IP;
    ip->VersionAndLength = 0x45; // IPv4, header 5*4 bytes
    ip->DSCPandECN = 0;
    ip->TotalLength = htons(28); // IP header + UDP header, no payload
    ip->ID = htons(0);
    ip->FlagsAndOffset = htons(0);
    ip->TTL = 64;
    ip->Protocol = 0x11; // UDP
    for (i = 0; i < 4; ++i) {
        ip->Source[i] = SourceIP[i];
        ip->Dest[i] = DestIP[i];
    }
    SetIPCheckSum(ip);

    packet->UDP->SourcePort = htons(10000);
    packet->UDP->DestPort = htons(10001);
    packet->UDP->Length = htons(8);   // UDP header length
    SetUDPCheckSum(packet->IP, packet->UDP);
    packet->Size = 42;  // All headers, no payload
}

const int MXUDP = 1472;

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

void SetData(struct TUDPPacket *packet, uint8_t* data, uint16_t dataLen) {
    if (dataLen > MXUDP) {
        dataLen = MXUDP;
        fprintf(stderr, "too much data");
    }
    memcpy(packet->UDP->Payload, data, dataLen);
    SetDataLen(packet, dataLen);
}

void SendTestTraffic(char* device) {
    /*if (device == NULL) {
        int res = GetDefaultDevice(device);
        if (res)
            return res;
    }*/
    struct TUDPPacket packet;
    InitUDPPacket(&packet);
    char s[] = "7";
    SetData(&packet, s, sizeof(s));
    pcap_t* pd;
    pcap_dumper_t* pdumper;
    struct pcap_pkthdr header;
    pd = pcap_open_dead(DLT_EN10MB, 65535);
    pdumper = pcap_dump_open(pd, "dump.pcap");
    header.ts.tv_sec = 1;
    header.ts.tv_usec = 2;
    header.caplen = packet.Size;
    header.len = packet.Size;
    pcap_dump((u_char* ) pdumper, &header, (u_char *) &packet.Ethernet);
    return;
/*    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("test.cap", errbuf);
    const u_char* packet;
    struct pcap_pkthdr header;
    int i;
    for (i = 0; i < 3; ++i) {
        packet = pcap_next(handle, &header);
        if (packet == NULL)
            printf("null\n");
        else
        {
            printf("len: %d\n", header.len);
            int j;
            for (j = 0; j < header.len; ++j)
            {
                printf("%c", packet[j]);
            }
            return;
        }
    }
*/}

int main(int argc, char *argv[])
{
    int c;
    int hasArgs = 0;
    char* device = NULL;
    while((c = getopt(argc, argv, "lhd:t")) != -1) {
        hasArgs = 1;
        switch (c)
        {
        case 'l':
            return PrintAllDevices();
        case 'h':
            PrintHelp(argv[0]);
            return 1;
        case 'd':
            device = optarg;
            break;
        }
    }
    SendTestTraffic(device);
    return 0;
    if (!hasArgs) {
        PrintHelp(argv[0]);
        return 1;
    }
    return 0;
}
