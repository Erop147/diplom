#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>

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

struct TEthernet {
    uint8_t Dest[6];
    uint8_t Source[6];
    uint16_t Type;
    uint8_t Payload[1500];
};

struct TIP {
    uint8_t VersionAndLength;
    uint8_t Flags;
    uint16_t TotalLength;
    uint16_t ID;
    uint16_t FlagsAndOffset;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t CheckSum;
    uint8_t Source[4];
    uint8_t Dest[4];
    uint8_t Payload[1480];
};

struct TUDP {
    uint16_t SourcePort;
    uint16_t DestPort;
    uint16_t Length;
    uint16_t CheckSum;
    uint8_t Payload[1472];
};

struct UDPPacket
{
    struct TEthernet Ethernet;
    struct TIP* IP;
    struct TUDP* UDP;
};

void SendTestTraffic(char* device) {
    /*if (device == NULL) {
        int res = GetDefaultDevice(device);
        if (res)
            return res;
    }*/
    char errbuf[PCAP_ERRBUF_SIZE];
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
}

int main(int argc, char *argv[])
{
    printf("%d\n", sizeof(uint16_t));
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
