#ifndef _NETTEST_TESTS_H_
#define _NETTEST_TESTS_H_

#include "config.h"

typedef int (*TTestFuncPointer) (const struct TConfig* config);

int ManyNetworksTest(const struct TConfig* config);
int DifferentPayloadSizeTest(const struct TConfig* config);
int LowTTLTest(const struct TConfig* config);
int BadMacTest(const struct TConfig* config);

extern TTestFuncPointer Tests[];
extern const int TestsCount;
extern const char TestNames[][32];

#endif
