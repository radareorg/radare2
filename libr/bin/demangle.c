/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */

#include <r_bin.h>

R_API char *r_bin_demangle_java(const char *str) {
	return NULL;
}

R_API char *r_bin_demangle_cxx(const char *str) {
	return NULL;
}

R_API char *r_bin_demangle (RBin *bin, const char *str, int type) {
	switch (type) {
	case R_BIN_NM_JAVA: return r_bin_demangle_java (str);
	case R_BIN_NM_CXX: return r_bin_demangle_cxx (str);
	case R_BIN_NM_ANY: 
		if (bin && bin->curarch.curplugin && bin->curarch.curplugin->demangle)
			return bin->curarch.curplugin->demangle (str);
		return NULL;
	}
	return NULL;
}
