#ifndef _E146_CONFIG_H_
#define _E146_CONFIG_H_

#include <stdint.h>

struct TMainConfig {
    uint8_t SourceMac[6];
    uint8_t DestMac[6];
    uint8_t FakeDestMac[6];
    uint8_t SourceIP[6];
    uint8_t DestIP[6];
    char Device[64];
};

struct TManyNetworkConfig {
    int PacketsPerTest;
    int Start;
    int Step;
    int TestsCount;
};

struct TDifferentPayloadConfig {
    int PacketsPerTest;
    int Start;
    int Step;
    int TestsCount;
};

struct TLowTTLConfig {
    int PacketsPerTest;
    double Start;
    double Step;
    int TestsCount;
};

struct TBadMacConfig {
    int PacketsPerTest;
    double Start;
    double Step;
    int TestsCount;
};

struct TConfig {
    struct TMainConfig MainConfig;
    struct TDifferentPayloadConfig DifferentPayloadConfig;
    struct TManyNetworkConfig ManyNetworkConfig;
    struct TLowTTLConfig LowTTLConfig;
    struct TBadMacConfig BadMacConfig;
};

int LoadConfig(struct TConfig* config, const char* fileName, int writeDefault);
int WriteDefaultConfig(const char* fileName);

#endif
