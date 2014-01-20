#ifndef _E146_TESTSUTILS_H_
#define _E146_TESTSUTILS_H_

#include "structures.h"
#include "config.h"

#include <pcap.h>

extern const char ColumnTest[];
extern const char ColumnRecived[];
extern const char ColumnRecivedPercent[];
extern const char ColumnAvgSize[];
extern const char ColumnAvgPayload[];
extern const char ColumnTime[];
extern const char ColumnSpeed[];
extern const char ColumnPayloadSpeed[];
extern const char ColumnPPS[];
extern const char ColumnSended[];
extern const char ColumnNetworks[];
extern const char ColumnBadPackets[];

void WaitFor(struct timeval ts);
int SendPacket(struct TUDPPacket* packet, struct timeval ts);
int InitWriter(const char* name);
int InitReader(const char* name);
int32_t GetTestNum(int32_t packetNum);
void Reset(int32_t packetNum);
double GetTestTime();
void PrintStat(int update);
void ReaderCallback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int ReadPackets(const struct TConfig* config);
int FinishWriter();
uint8_t ReverseBits(uint8_t x);
void WriteIntToBytes(char* dest, int32_t val);
void WritePacketNum(char* dest, int32_t packetNum);
int32_t ReadIntFromBytes(uint8_t* src);
int32_t ReadPacketNum(char* src);
void WriteReversed(char* dest, int32_t data, int cnt);

#endif

