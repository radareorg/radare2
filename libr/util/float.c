/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_util.h"

R_API int r_num_is_float(struct r_num_t *num, const char *str)
{
	// TODO: also support 'f' terminated strings
	return (int) strchr (str, '.');
}

R_API double r_num_get_float(struct r_num_t *num, const char *str)
{
	double d = 0.0f;
	sscanf (str, "%lf", &d);
	return d;
}
