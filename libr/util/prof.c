/* radare - LGPL - Copyright 2009-2021 - pancake */

#include "r_util.h"

typedef struct timeval tv;

// Subtract the 'tv' values when from end, storing result in RESULT
// Return 1 if the difference is negative, otherwise 0.
static int timeval_subtract(tv *result, tv *end, tv *when) {
	// Perform the carry for the later subtraction by updating Y
	if (end->tv_usec < when->tv_usec) {
		int nsec = (when->tv_usec - end->tv_usec) / 1000000 + 1;
		when->tv_usec -= 1000000 * nsec;
		when->tv_sec += nsec;
	}
	if (end->tv_usec - when->tv_usec > 1000000) {
		int nsec = (end->tv_usec - when->tv_usec) / 1000000;
		when->tv_usec += 1000000 * nsec;
		when->tv_sec -= nsec;
	}

	// Compute the time remaining to wait. 'tv_usec' is certainly positive.
	result->tv_sec = end->tv_sec - when->tv_sec;
	result->tv_usec = end->tv_usec - when->tv_usec;

	// Return 1 if result is negative
	return end->tv_sec < when->tv_sec;
}

R_API void r_prof_start(struct r_prof_t *p) {
	tv *when = &p->when;
	p->result = 0.0;
	gettimeofday(when, NULL);
}

R_API double r_prof_end(struct r_prof_t *p) {
	tv end, diff, *when = &p->when;
	int sign;
	gettimeofday (&end, NULL);
	sign = timeval_subtract (&diff, when, &end);
	p->result = R_ABS (((double)(diff.tv_sec)
		+ ((double)diff.tv_usec / 1000000.)));
	return R_ABS (sign);
}
