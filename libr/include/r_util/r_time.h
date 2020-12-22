#ifndef R2_TIME_H
#define R2_TIME_H

#include <r_types.h>
#include <time.h>

#define R_NSEC_PER_SEC  1000000000ULL
#define R_NSEC_PER_MSEC 1000000ULL
#define R_USEC_PER_SEC  1000000ULL
#define R_NSEC_PER_USEC 1000ULL
#define R_USEC_PER_MSEC 1000ULL

#define ASCTIME_BUF_MINLEN (26)

// wall clock time in microseconds
R_API ut64 r_time_now(void);

// monotonic time in microseconds
R_API ut64 r_time_now_mono(void);

R_API char *r_time_stamp_to_str(ut32 timeStamp);
R_API ut32 r_time_dos_time_stamp_to_posix(ut32 timeStamp);
R_API bool r_time_stamp_is_dos_format(const ut32 certainPosixTimeStamp, const ut32 possiblePosixOrDosTimeStamp);
R_API const char *r_time_to_string(ut64 ts);

// Cross platform thread-safe time functions
R_API char *r_asctime_r(const struct tm *tm, char *buf);
R_API char *r_ctime_r(const time_t *timer, char *buf);

#define R_TIME_PROFILE_ENABLED 0

#if R_TIME_PROFILE_ENABLED
#define R_TIME_PROFILE_BEGIN ut64 __now__ = r_time_now_mono()
#define R_TIME_PROFILE_END eprintf ("%s %"PFMT64d"\n", __FUNCTION__, r_time_now_mono() - __now__)
#else
#define R_TIME_PROFILE_BEGIN do{}while(0)
#define R_TIME_PROFILE_END do{}while(0)
#endif

#endif
