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

    iniparser_freedict(dict);
    return 0;
}

int WriteDefaultConfig(const char* fileName) {
    FILE* f = fopen(fileName, "w");
}
