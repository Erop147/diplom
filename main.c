#include "structures.h"
#include "udp.h"

#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>

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


void SendTestTraffic(char* device) {
    struct TUDPPacket packet;
    InitUDPPacket(&packet);
    const int DATASIZE = 100;
    char data[DATASIZE];
    memset(data, 'x', sizeof(data));
    SetData(&packet, data, sizeof(data));
    pcap_t* pd;
    pcap_dumper_t* pdumper;
    struct pcap_pkthdr header;
    pd = pcap_open_dead(DLT_EN10MB, 65535);
    pdumper = pcap_dump_open(pd, "dump.pcap");
    int i;
    for (i = 0; i < 10; ++i) {
        SetPort(&packet, 10000 + i%100, 20000 + i%100);
        header.ts.tv_sec = i;
        header.ts.tv_usec = 0;
        header.caplen = packet.Size;
        header.len = packet.Size;
        pcap_dump((u_char* ) pdumper, &header, (u_char *) &packet.Ethernet);
    }
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
