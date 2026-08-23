/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <sys/types.h>
#include <sys/select.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct timeval {
	time_t tv_sec;
	suseconds_t tv_usec;
};

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

struct itimerval {
	struct timeval it_interval;
	struct timeval it_value;
};

#define ITIMER_REAL 0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF 2

int gettimeofday(struct timeval *tv, struct timezone *tz);
int settimeofday(const struct timeval *tv, const struct timezone *tz);
int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
int getitimer(int which, struct itimerval *curr_value);
int utimes(const char *filename, const struct timeval times[2]);

#define timerclear(tvp) ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define timerisset(tvp) ((tvp)->tv_sec || (tvp)->tv_usec)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TIME_H */
