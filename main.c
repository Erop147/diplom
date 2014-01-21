#include "structures.h"
#include "udp.h"
#include "ts_util.h"
#include "tests.h"
#include "testutils.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>

static int PrintDefaultDevice() {
    char* dev;
    int res = GetDefaultDevice(&dev);
    if (res)
        return res;
    printf("Default device:\n%s\n\n", dev);
    return 0;
}

static int PrintAllDevices() {
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

static void PrintHelp(const char* progName) {
    fprintf(stderr,
        "USAGE: %s [-lh] [-f config] [-m mode]\n"
        "\n"
        "-l          print list of suitable devices. Must be root\n"
        "-h          print this help\n"
        "-f config   file with config, default: config.ini\n"
        "            creates default if it doesn't exists\n"
        "-m mode     mode can be write or read\n"
        "            write - sends tests to net or writes it\n"
        "            to stdout in pcap format\n"
        "            read - reads from stdout or net\n"
        , progName
    );
}

static int WriteTest(const struct TConfig* config) {
    int i;
    for (i = 0; i < TestsCount; ++i) {
        if (strcmp(config->MainConfig.Test, TestNames[i]) == 0)
            return (*Tests[i])(config);
    }
    fprintf(stderr, "Unknown test: %s\n", config->MainConfig.Test);
    return 1;
}

static int ReadTest(const struct TConfig* config) {
    return ReadPackets(config);
}

const char defaultConfig[] = "config.ini";
const char defaultMode[] = "";
int main(int argc, char *argv[])
{
    int c;
    int hasArgs = 0;
    const char* configFile = NULL;
    const char* mode = defaultMode;

    while((c = getopt(argc, argv, "lhf:m:")) != -1) {
        hasArgs = 1;
        switch (c)
        {
        case 'l':
            return PrintAllDevices();
        case 'h':
            PrintHelp(argv[0]);
            return 1;
        case 'f':
            configFile = optarg;
            break;
        case 'm':
            mode = optarg;
            break;
        }
    }
    if (!hasArgs) {
        PrintHelp(argv[0]);
        return 1;
    }
    int createMode = 0;
    if (configFile == NULL) {
        createMode = 1;
        configFile = defaultConfig;
    }
    struct TConfig config;
    if (LoadConfig(&config, configFile, createMode))
        return 1;
    if (strcmp(mode, "write") == 0)
        return WriteTest(&config);
    if (strcmp(mode, "read") == 0)
        return ReadTest(&config);
    fprintf(stderr, "Unknown mode: %s\n", mode);
    PrintHelp(argv[0]);
    return 1;
}
