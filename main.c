#include "structures.h"
#include "udp.h"
#include "ts_util.h"
#include "tests.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>

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
    }
    Finish();
    return 0;
}

int main(int argc, char *argv[])
{
    struct TConfig config;
    if (LoadConfig(&config, "config.ini", 0))
        return 1;
    int i;
    for (i = 0; i < TestsCount; ++i) {
        if (strcmp(config.MainConfig.Test, TestNames[i]) == 0)
            return (*Tests[i])(&config);
    }
    fprintf(stderr, "Unknown test: %s\n", config.MainConfig.Test);
    return 1;
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
    if (!hasArgs) {
        PrintHelp(argv[0]);
        return 1;
    }
    return 0;
}
