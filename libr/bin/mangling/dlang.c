/* radare - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>
#include "cxx2/cxx2.h"

R_API char *r_bin_demangle_dlang(const char *str) {
	return r_demangle_dlang (str);
}
