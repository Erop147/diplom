#include <stdint.h>

struct TEthernet {
    uint8_t Dest[6];
    uint8_t Source[6];
    uint16_t Type;
    uint8_t Payload[1500];
};

struct TIP {
    uint8_t VersionAndLength;
    uint8_t DSCPandECN;
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

struct TUDPPacket
{
    struct TEthernet Ethernet;
    struct TIP* IP;
    struct TUDP* UDP;
    uint16_t Size;
};
