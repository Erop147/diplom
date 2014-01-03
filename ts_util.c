#include "ts_util.h"

int TsCompare (struct timespec time1, struct timespec time2) {
    if (time1.tv_sec < time2.tv_sec)
        return -1;
    else if (time1.tv_sec > time2.tv_sec)
        return 1;
    else if (time1.tv_nsec < time2.tv_nsec)
        return -1;
    else if (time1.tv_nsec > time2.tv_nsec)
        return 1;
    else
        return 0;
}

struct timespec TsAdd (struct timespec time1, struct timespec time2) {
    struct  timespec  result ;

    result.tv_sec = time1.tv_sec + time2.tv_sec;
    result.tv_nsec = time1.tv_nsec + time2.tv_nsec;
    if (result.tv_nsec >= 1000000000L) { /* Carry? */
        result.tv_sec++;
        result.tv_nsec -= 1000000000L;
    }
    return result;
}

struct timespec TsSubtract (struct timespec time1, struct timespec time2) {
    struct timespec result;
    if (TsCompare(time1, time2) < 0) {
        result.tv_sec = result.tv_nsec = 0;
    } else {
        result.tv_sec = time1.tv_sec - time2.tv_sec;
        if (time1.tv_nsec < time2.tv_nsec) {
            result.tv_nsec = time1.tv_nsec + 1000000000L - time2.tv_nsec;
            result.tv_sec--;
        } else {
            result.tv_nsec = time1.tv_nsec - time2.tv_nsec ;
        }
    }
    return result;
}

void TimevalToTimespec (struct timeval* time1, struct timespec* time2) {
    time2->tv_sec = time1->tv_sec;
    time2->tv_nsec = time1->tv_usec * 1000;
}
