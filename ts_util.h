#ifndef E146_TS_UTIL_H
#define E146_TS_UTIL_H

#include <time.h>
#include <sys/time.h>

int TsCompare (struct timespec time1, struct timespec time2);
struct timespec TsAdd (struct timespec time1, struct timespec time2);
struct timespec TsSubtract (struct timespec time1, struct timespec time2);
void TimevalToTimespec (struct timeval* time1, struct timespec* time2);

#endif
