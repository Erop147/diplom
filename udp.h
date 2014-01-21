#ifndef _NETTEST_UDP_H
#define _NETTEST_UDP_H

#include "structures.h"
#include "config.h"

extern const int MXUDP;

void InitUDPPacket(struct TUDPPacket* packet, const struct TMainConfig* mainConfig);
void SetDataLen(struct TUDPPacket* packet, uint16_t dataLen);
void SetTTL(struct TUDPPacket* packet, uint8_t ttl);
void SetIP(struct TUDPPacket* packet, const uint8_t* sourceIP, const uint8_t* destIP) ;
void SetPort(struct TUDPPacket* packet, uint16_t sourcePort, uint16_t destPort);
void SetData(struct TUDPPacket* packet, const uint8_t* data, uint16_t dataLen);
void SetMac(struct TUDPPacket* packet, const uint8_t* source, const uint8_t* dest);

#endif
