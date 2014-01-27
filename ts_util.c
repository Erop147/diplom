#include "ts_util.h"

int TsCompare(const struct timespec time1, const struct timespec time2) {
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

struct timespec TsAdd(const struct timespec time1, const struct timespec time2) {
    struct timespec result;

    result.tv_sec = time1.tv_sec + time2.tv_sec;
    result.tv_nsec = time1.tv_nsec + time2.tv_nsec;
    if (result.tv_nsec >= 1000000000L) { // Carry?
        result.tv_sec++;
        result.tv_nsec -= 1000000000L;
    }
    return result;
}

struct timespec TsSubtract(const struct timespec time1, const struct timespec time2) {
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

void TimevalToTimespec(const struct timeval* from, struct timespec* to) {
    to->tv_sec = from->tv_sec;
    to->tv_nsec = from->tv_usec * 1000;
}

struct timeval TvAdd(const struct timeval time1, uint32_t delta) {
    struct timeval result = time1;
    result.tv_sec += delta / 1000000L;
    result.tv_usec += delta % 1000000L;
    if (result.tv_usec >= 1000000L) {
        ++result.tv_sec;
        result.tv_usec -= 1000000L;
    }
    return result;
}
