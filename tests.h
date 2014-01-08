#ifndef _E146_TESTS_H_
#define _E146_TESTS_H_

#include "config.h"

int ManyNetworksTest(const struct TConfig* config);
void DifferentPayloadSizeTest(const struct TConfig* config);
void LowTTLTest(const struct TConfig* config);
void BadMacTest(const struct TConfig* config);

#endif
