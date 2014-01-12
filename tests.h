#ifndef _E146_TESTS_H_
#define _E146_TESTS_H_

#include "config.h"

typedef int (*TTestFuncPointer) (const struct TConfig* config);

int ManyNetworksTest(const struct TConfig* config);
int DifferentPayloadSizeTest(const struct TConfig* config);
int LowTTLTest(const struct TConfig* config);
int BadMacTest(const struct TConfig* config);

extern TTestFuncPointer Tests[];
extern int TestsCount;
extern char TestNames[][32];

#endif
