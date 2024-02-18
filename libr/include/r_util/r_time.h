#ifndef R2_TIME_H
#define R2_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_types.h>
#include <time.h>

#define R_NSEC_PER_SEC  1000000000ULL
#define R_NSEC_PER_MSEC 1000000ULL
#define R_USEC_PER_SEC  1000000ULL
#define R_NSEC_PER_USEC 1000ULL
#define R_USEC_PER_MSEC 1000ULL

#define ASCTIME_BUF_MAXLEN (26)

// current calendar time, alias for time(0). affected by calendar, timezone changes, localtime, etc
R_API ut64 r_time_today(void);

// wall clock time in microseconds
R_API ut64 r_time_now(void);

// monotonic time in microseconds
R_API ut64 r_time_now_mono(void);

R_API R_MUSTUSE char *r_time_secs_tostring(time_t timeStamp);
R_API R_MUSTUSE char *r_time_usecs_tostring(ut64 ts);

R_API int r_time_beats(ut64 ts, int *sub);

R_API ut64 r_time_dos_today(ut32 timeStamp, int tz);
R_API ut64 r_time_hfs_today(ut32 hfsts, int tz);
R_API ut64 r_time_unix_today(ut32 unxts, int tz);
R_API ut64 r_time_w32_today(ut64 ts, int tz);

// Cross platform thread-safe time functions
R_API char *r_asctime_r(const struct tm *tm, char *buf);
R_API char *r_ctime_r(const time_t *timer, char *buf);

/** profiling */
typedef struct r_prof_t {
	struct timeval when;
	double result;
} RProfile;
R_API void r_prof_start(RProfile *p);
R_API double r_prof_end(RProfile *p);

#define R_TIME_PROFILE_ENABLED 0

#if R_TIME_PROFILE_ENABLED
#define R_TIME_PROFILE_BEGIN ut64 __now__ = r_time_now_mono()
#define R_TIME_PROFILE_END eprintf ("%s %"PFMT64d"\n", __FUNCTION__, r_time_now_mono() - __now__)
#else
#define R_TIME_PROFILE_BEGIN do{}while(0)
#define R_TIME_PROFILE_END do{}while(0)
#endif

#ifdef __cplusplus
}
#endif

#endif
