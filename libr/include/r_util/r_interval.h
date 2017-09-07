#ifndef	R_INTERVAL_H
#define	R_INTERVAL_H

#include <r_types.h>

typedef enum {
	R_INTERVAL_UNDEFINED = 0,
	R_INTERVAL_OPEN_OPEN,
	R_INTERVAL_OPEN_CLOSED,
	R_INTERVAL_CLOSED_OPEN,
	R_INTERVAL_CLOSED_CLOSED
} RIntervalType;

typedef struct r_interval_t {
	RIntervalType type;
	ut64 from;
	ut64 to;
} RInterval;

//from is the first element IN the interval
R_API bool r_interval_init (RInterval *interv, RIntervalType type, ut64 from, ut64 size);
//returns first element IN the interval
R_API ut64 r_interval_first (RInterval interv, bool *err);
//returns last element IN the interval
R_API ut64 r_interval_last (RInterval interv, bool *err);
//returns number of elements in the interval
//if the *err is true, the interval was hand-initialized by hand in the wrong way, so that the size extends ut64
R_API ut64 r_interval_size (RInterval interv, bool *err);
//number of elements starting at from to the last, INCLUDING the last element
//if the *err is true, the interval was hand-initialized by hand in the wrong way, so that the size extends ut64, or from is not inside the interval
R_API ut64 r_interval_to_end (RInterval interv, ut64 from, bool *err);
R_API ut64 r_interval_intersection_lower_bound (RInterval inter, RInterval val, bool *intersection);
R_API ut64 r_interval_instersection_upper_bound (RInterval inter, RInterval val, bool *intersection);
R_API bool r_interval_in_me (RInterval interv, ut64 you);

#endif
