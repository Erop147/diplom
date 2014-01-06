#ifndef E146_UDP_H
#define E146_udp_h

#include "structures.h"

extern uint8_t SourceMac[6];
extern uint8_t DestMac[6];
extern uint8_t FakeDestMac[6];
extern uint8_t SourceIP[4];
extern uint8_t DestIP[4];
extern const int MXUDP;

void InitUDPPacket(struct TUDPPacket* packet);
void SetDataLen(struct TUDPPacket* packet, uint16_t dataLen);
void SetTTL(struct TUDPPacket* packet, uint8_t ttl);
void SetIP(struct TUDPPacket* packet, uint8_t* sourceIP, uint8_t* destIP) ;
void SetPort(struct TUDPPacket* packet, uint16_t sourcePort, uint16_t destPort);
void SetData(struct TUDPPacket* packet, uint8_t* data, uint16_t dataLen);
void SetMac(struct TUDPPacket* packet, uint8_t* source, uint8_t* dest);

#endif
