#ifndef _NETTEST_CONFIG_H_
#define _NETTEST_CONFIG_H_

#include <stdint.h>

struct TMainConfig {
    uint8_t SourceMac[6];
    uint8_t DestMac[6];
    uint8_t SourceIP[6];
    uint8_t DestIP[6];
    char Device[64];
    char Test[64];
    uint32_t PacketsPerTest;
    uint32_t FlushEach;
    uint32_t Delay;
};

struct TManyNetworkConfig {
    int Start;
    int Step;
    int TestsCount;
};

struct TDifferentPayloadConfig {
    int Start;
    int Step;
    int TestsCount;
};

struct TLowTTLConfig {
    double Start;
    double Step;
    int TestsCount;
};

struct TBadMacConfig {
    double Start;
    double Step;
    int TestsCount;
    uint8_t FakeDestMac[6];
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
