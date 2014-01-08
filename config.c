#include "config.h"
#include "iniparser.h"

#include <stdio.h>

int ReadMacFromStr(const char* str, uint8_t* mac, const char* errpref) {
    if (str == NULL) {
        fprintf(stderr, "%s no such field\n", errpref);
        return 1;
    }
    int i;
    if (strlen(str) != 12) {
        fprintf(stderr, "%s length must be 12 hexadecimal symbols, but was %ld\n", errpref, strlen(str));
        return 1;
    }
    for (i = 0; i < 6; ++i) {
        sscanf(str + i*2, "%2hhx", mac + i);
    }
    return 0;
}

int ReadIPFromStr(const char* str, uint8_t* ip, const char* errpref) {
    if (str == NULL) {
        fprintf(stderr, "%s no such field\n", errpref);
        return 1;
    }
    int i;
    for (i = 0; i < 4; ++i) {
        if (i) {
            while (*str != '.')
                ++str;
            ++str;
        }
        sscanf(str, "%hhd", ip + i);
    }
    return 0;
}

int LoadConfig(struct TConfig* config, const char* fileName, int writeDefault) {
    dictionary* dict = iniparser_load(fileName);
    if (dict == NULL) {
        if (writeDefault)
            WriteDefaultConfig(fileName);
        return 1;
    }
    int res = ReadMacFromStr(iniparser_getstring(dict, "main:SourceMac", NULL), (uint8_t*) &config->MainConfig.SourceMac, "SourceMac:");
    if (res)
        return res;
    res = ReadMacFromStr(iniparser_getstring(dict, "main:DestMac", NULL), (uint8_t*) &config->MainConfig.DestMac, "DestMac:");
    if (res)
        return res;
    res = ReadMacFromStr(iniparser_getstring(dict, "main:FakeDestMac", NULL), (uint8_t*) &config->MainConfig.FakeDestMac, "FakeDestMac:");
    if (res)
        return res;
    res = ReadIPFromStr(iniparser_getstring(dict, "main:SourceIP", NULL), (uint8_t*) &config->MainConfig.SourceIP, "SourceIP:");
    if (res)
        return res;
    res = ReadIPFromStr(iniparser_getstring(dict, "main:DestIP", NULL), (uint8_t*) &config->MainConfig.DestIP, "DestIP:");
    if (res)
        return res;

    char* device = iniparser_getstring(dict, "main:Device", NULL);
    if (device == NULL) {
        fprintf(stderr, "Device: no such field\n");
        return 1;
    }
    strncpy(config->MainConfig.Device, device, sizeof(config->MainConfig.Device) - 1);
    config->MainConfig.Device[sizeof(config->MainConfig.Device) - 1] = 0;

    iniparser_freedict(dict);
    return 0;
}

const int confSize = 6;
const char defaultConf[][2][20] = {
        {"main:SourceMac", "001d72ca0a49"},
        {"main:DestMac", "1c7ee5e05e12"},
        {"main:FakeDestMac", "5c260a128735"},
        {"main:SourceIP", "192.168.0.10"},
        {"main:DestIP", "192.168.1.11"},
        {"main:Device", "-"}
};

const int sectionsSize = 1;
const char sections[][20] = {
    "main",
};

int WriteDefaultConfig(const char* fileName) {
    fprintf(stderr, "Writing default config to %s\n", fileName);
    dictionary* dict = dictionary_new(0);
    int i;
    for (i = 0; i < sectionsSize; ++i) {
        iniparser_set(dict, sections[i], NULL);
    }
    for (i = 0; i < confSize; ++i) {
        iniparser_set(dict, defaultConf[i][0], defaultConf[i][1]);
    }
//    FILE* f = fopen(fileName, "w");
    iniparser_dump_ini(dict, stdout);
    iniparser_freedict(dict);
}
