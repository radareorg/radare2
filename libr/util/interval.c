#include <r_util.h>

R_API bool r_interval_init (RInterval *interv, RIntervalType type, ut64 from, ut64 size) {
	if (!size || !interv) {
		return false;
	}
	interv->type = type;
	switch (type) {
		case R_INTERVAL_OPEN_OPEN:
			interv->from = from - 1;
			interv->to = from + size;
			break;
		case R_INTERVAL_OPEN_CLOSED:
			interv->from = from - 1;
			interv->to = interv->from + size;
			break;
		case R_INTERVAL_CLOSED_OPEN:
			interv->from = from;
			interv->to = from + size;
			break;
		case R_INTERVAL_CLOSED_CLOSED:
			interv->from = from;
			interv->to = from + size - 1;
			break;
		case R_INTERVAL_UNDEFINED:
		default:
			return false;
	}
	if (r_interval_first (*interv, NULL) > r_interval_last (*interv, NULL)) {
		//This is a hack, for my lazyness
		r_interval_init (interv, R_INTERVAL_CLOSED_CLOSED, from, UT64_MAX - from + 1);
		interv->type = type;
	}
	return true;
}

R_API ut64 r_interval_first (RInterval interv, bool *err) {
	switch (interv.type) {
		case R_INTERVAL_OPEN_OPEN:
		case R_INTERVAL_OPEN_CLOSED:
			return interv.from + 1;
		case R_INTERVAL_CLOSED_OPEN:
		case R_INTERVAL_CLOSED_CLOSED:
			return interv.from;
	}
	if (err) {
		*err = true;
	}
	return 0LL;
}

R_API ut64 r_interval_last (RInterval interv, bool *err) {
	switch (interv.type) {
		case R_INTERVAL_OPEN_OPEN:
		case R_INTERVAL_CLOSED_OPEN:
			return interv.to - 1;
		case R_INTERVAL_OPEN_CLOSED:
		case R_INTERVAL_CLOSED_CLOSED:
			return interv.to;
	}
	if (err) {
		*err = true;
	}
	return 0LL;
}

R_API ut64 r_interval_size (RInterval interv, bool *err) {
	ut64 from = r_interval_first (interv, err);
	ut64 to = r_interval_last (interv, err);
	if (err && *err) {
		return 0LL;
	}
	return to - from + 1;
}

R_API ut64 r_interval_to_end (RInterval interv, ut64 from, bool *err) {
	ut64 size = r_interval_size (interv, err);
	if (err && *err) {
		return 0LL;
	}
	if (size < (from - r_interval_first (interv, err) + 1)) {
		if (err) {
			*err = true;
		}
		return 0LL;
	}
	return r_interval_last (interv, err) - from + 1;
}

R_API ut64 r_interval_intersection_lower_bound (RInterval inter, RInterval val, bool *intersection) {
	ut64 from0, to0, from1, to1;
	from0 = r_interval_first (inter, NULL);
	to0 = r_interval_last (inter, NULL);
	from1 = r_interval_first (val, NULL);
	to1 = r_interval_last (val, NULL);
// this covers these cases of intersection
// ####inter####
//             ######val###
//
// #####inter######
//   ####val####
//
// ####inter####
// ##val##
	if ((from0 <= from1) && (from1 <= to0)) {
		*intersection = true;
		return from1;
	}
// this covers these cases of intersection
//          ########inter#######
// #######val######
//
//    #####inter######
// ##########val#########
//
// ##inter##
// #####val#####
	if ((from1 <= from0) && (from0 <= to0)) {
		*intersection = true;
		return  from0;
	}
	*intersection = false;
	return 0LL;
}

R_API ut64 r_interval_instersection_upper_bound (RInterval inter, RInterval val, bool *intersection) {
	ut64 from0, to0, from1, to1;
	from0 = r_interval_first (inter, NULL);
	to0 = r_interval_last (inter, NULL);
	from1 = r_interval_first (val, NULL);
	to1 = r_interval_last (val, NULL);
// this covers these cases of intersection
//          ########inter#######
// #######val######
//
// #####inter######
//   ####val####
//
// ######inter########
//    #######val######
	if ((from0 <= to1) && (to1 <= to0)) {
		*intersection = true;
		return to1;
	}
// this covers these cases of intersection
// ####inter####
//             ######val###
//
//    #####inter######
// ##########val#########
//
//     ##inter##
// #####val#####
	if ((from1 <= to0) && (to0 <= to1)) {
		*intersection = true;
		return to0;
	}
	*intersection = false;
	return 0LL;
}

R_API bool r_interval_in_me (RInterval interv, ut64 you) {
	ut64 from = r_interval_first (interv, NULL),
	     to = r_interval_last (interv, NULL);
	if ((from <= you) && (you <= to)) {
		return true;
	}
	return false;
}
