/* radare - LGPL - Copyright 2016 - condret */

#include <r_util.h>
#include <r_types.h>

R_API ut64 r_chk_overflow_add_ut64 (ut64 a, ut64 b)
{
	if ((UT64_MAX - b) < a)
		return UT64_MAX - a;
	return b;
}
