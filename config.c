#include "config.h"
#include "iniparser.h"
#include "macroses.h"

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

int ReadString(const char* source, char* dest, int maxlen, const char* errpref) {
    if (source == NULL) {
        fprintf(stderr, "%s no such field\n", errpref);
        return 1;
    }
    strncpy(dest, source, maxlen - 1);
    dest[maxlen - 1] = 0;
    return 0;
}

int ReadInt(const char* source, int* dest, const char* errpref) {
    if (source == NULL) {
        fprintf(stderr, "%s no such field\n", errpref);
        return 1;
    }
    sscanf(source, "%d", dest);
    return 0;
}

int ReadDouble(const char* source, double* dest, const char* errpref) {
    if (source == NULL) {
        fprintf(stderr, "%s no such field\n", errpref);
        return 1;
    }
    sscanf(source, "%lf", dest);
    return 0;
}

int LoadConfig(struct TConfig* config, const char* fileName, int writeDefault) {
    dictionary* dict = iniparser_load(fileName);
    if (dict == NULL) {
        if (writeDefault)
            WriteDefaultConfig(fileName);
        return 1;
    }

///// Main Config /////

    if (ReadMacFromStr(iniparser_getstring(dict, "main:source_mac", NULL), (uint8_t*) &config->MainConfig.SourceMac, "main:source_mac:"))
        return 1;
    if (ReadMacFromStr(iniparser_getstring(dict, "main:dest_mac", NULL), (uint8_t*) &config->MainConfig.DestMac, "main:dest_mac:"))
        return 1;
    if (ReadMacFromStr(iniparser_getstring(dict, "main:fake_dest_mac", NULL), (uint8_t*) &config->MainConfig.FakeDestMac, "main:fake_dest_mac:"))
        return 1;
    if (ReadIPFromStr(iniparser_getstring(dict, "main:source_ip", NULL), (uint8_t*) &config->MainConfig.SourceIP, "main:source_ip:"))
        return 1;
    if (ReadIPFromStr(iniparser_getstring(dict, "main:dest_ip", NULL), (uint8_t*) &config->MainConfig.DestIP, "main:dest_ip:"))
        return 1;
    if (ReadString(iniparser_getstring(dict, "main:device", NULL), config->MainConfig.Device, sizeof(config->MainConfig.Device), "main:device:"))
        return 1;
    if (ReadString(iniparser_getstring(dict, "main:test", NULL), config->MainConfig.Test, sizeof(config->MainConfig.Test), "main:test:"))
        return 1;
    if (ReadInt(iniparser_getstring(dict, "main:packets_per_test", NULL), &config->MainConfig.PacketsPerTest, "main:packets_per_test:"))
        return 1;

///// Many Networks Config /////

    if (ReadInt(iniparser_getstring(dict, "many_networks:start", NULL), &config->ManyNetworkConfig.Start, "many_networks:start:"))
        return 1;
    if (ReadInt(iniparser_getstring(dict, "many_networks:step", NULL), &config->ManyNetworkConfig.Step, "many_networks:step:"))
        return 1;
    if (ReadInt(iniparser_getstring(dict, "many_networks:tests_count", NULL), &config->ManyNetworkConfig.TestsCount, "many_networks:tests_count:"))
        return 1;

///// Different Payload Config /////

    if (ReadInt(iniparser_getstring(dict, "different_payload:start", NULL), &config->DifferentPayloadConfig.Start, "different_payload:start:"))
        return 1;
    if (ReadInt(iniparser_getstring(dict, "different_payload:step", NULL), &config->DifferentPayloadConfig.Step, "different_payload:step:"))
        return 1;
    if (ReadInt(iniparser_getstring(dict, "different_payload:tests_count", NULL), &config->DifferentPayloadConfig.TestsCount, "different_pauload:tests_count:"))
        return 1;

///// Low TTL Config /////

    if (ReadDouble(iniparser_getstring(dict, "low_ttl:start", NULL), &config->LowTTLConfig.Start, "low_ttl:start:"))
        return 1;
    if (ReadDouble(iniparser_getstring(dict, "low_ttl:step", NULL), &config->LowTTLConfig.Step, "low_ttl:step:"))
        return 1;
    if (ReadInt(iniparser_getstring(dict, "low_ttl:tests_count", NULL), &config->LowTTLConfig.TestsCount, "low_ttl:tests_count:"))
        return 1;

///// Bad Mac Config /////

    if (ReadDouble(iniparser_getstring(dict, "bad_mac:start", NULL), &config->BadMacConfig.Start, "bad_mac:start:"))
        return 1;
    if (ReadDouble(iniparser_getstring(dict, "bad_mac:step", NULL), &config->BadMacConfig.Step, "bad_mac:step:"))
        return 1;
    if (ReadInt(iniparser_getstring(dict, "bad_mac:tests_count", NULL), &config->BadMacConfig.TestsCount, "bad_mac:tests_count:"))
        return 1;

    iniparser_freedict(dict);
    return 0;
}

const char defaultConf[][2][100] = {
        {"main:source_mac", "001d72ca0a49"},
        {"main:dest_mac", "1c7ee5e05e12"},
        {"main:fake_dest_mac", "5c260a128735"},
        {"main:source_ip", "192.168.0.10"},
        {"main:dest_ip", "192.168.1.11"},
        {"main:device", "-  ; \"-\" for stdout, \"default\" for default device, \"eth0\" for device eth0"},
        {"main:test", "many_networks"},
        {"main:packets_per_test", "10"},
        {"many_networks:start", "1"},
        {"many_networks:step", "3"},
        {"many_networks:test_count", "10"},
        {"different_pauload:start", "18"},
        {"different_pauload:step", "1"},
        {"different_pauload:test_count", "1470"},
        {"low_ttl:start", "0"},
        {"low_ttl:step", "0.1"},
        {"low_ttl:test_count", "10"},
        {"bad_mac:start", "0"},
        {"bad_mac:step", "0.1"},
        {"bad_mac:test_count", "10"}
};

const char sections[][20] = {
    "main",
    "many_networks",
    "different_pauload",
    "low_ttl",
    "bad_mac"
};

int WriteDefaultConfig(const char* fileName) {
    fprintf(stderr, "Writing default config to %s\n", fileName);
    dictionary* dict = dictionary_new(0);
    int i;
    for (i = 0; i < ARRAY_SIZE(sections); ++i) {
        iniparser_set(dict, sections[i], NULL);
    }
    for (i = 0; i < ARRAY_SIZE(defaultConf); ++i) {
        iniparser_set(dict, defaultConf[i][0], defaultConf[i][1]);
    }
//    FILE* f = fopen(fileName, "w");
    iniparser_dump_ini(dict, stdout);
    iniparser_freedict(dict);
    return 0;
}
