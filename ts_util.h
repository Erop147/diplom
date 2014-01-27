#ifndef _NETTEST_TS_UTIL_H
#define _NETTEST_TS_UTIL_H

#include <time.h>
#include <sys/time.h>
#include <stdint.h>

int TsCompare(const struct timespec time1, const struct timespec time2);
struct timespec TsAdd(const struct timespec time1, const struct timespec time2);
struct timespec TsSubtract(const struct timespec time1, const struct timespec time2);
void TimevalToTimespec(const struct timeval* frm, struct timespec* to);
struct timeval TvAdd(const struct timeval time1, uint32_t delta);

#endif
