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

pcap_t* pcap;
pcap_dumper_t* dumper;
int offline;

int Init(char* name) {
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

void WaitFor(struct timeval ts) {
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


int SendTestTraffic(char* device) {
    struct TUDPPacket packet;
    InitUDPPacket(&packet);
    const int DATASIZE = 1450;
    char data[DATASIZE];
    memset(data, 'x', sizeof(data));
    SetData(&packet, data, sizeof(data));
    int i;
    int res = Init("default");
    if (res)
        return res;
    struct timeval ts;
    ts.tv_sec = 0; // seconds from start
    ts.tv_usec = 0; // microseconds
    for (i = 0; i < 1000000; ++i) {
        SetPort(&packet, 10000 + i%100, 20000 + i%100);
        res = SendPacket(&packet, ts);
        if (res)
            return res;
//        fprintf(stderr, "%d", i);
    }
    Finish();
    return 0;
}

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
