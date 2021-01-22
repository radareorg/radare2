/* radare - LGPL - Copyright 2011-2019 - pancake */

#include <r_bin.h>
#include "i/private.h"
#include <cxx/demangle.h>

R_API void r_bin_demangle_list(RBin *bin) {
	const char *langs[] = { "c++", "java", "objc", "swift", "dlang", "msvc", "rust", NULL };
	RBinPlugin *plugin;
	RListIter *it;
	int i;
	if (!bin) {
		return;
	}
	for (i = 0; langs[i]; i++) {
		bin->cb_printf ("%s\n", langs[i]);
	}
	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->demangle) {
			bin->cb_printf ("%s\n", plugin->name);
		}
	}
}

R_API char *r_bin_demangle_plugin(RBin *bin, const char *name, const char *str) {
	RBinPlugin *plugin;
	RListIter *it;
	if (bin && name && str) {
		r_list_foreach (bin->plugins, it, plugin) {
			if (plugin->demangle && !strncmp (plugin->name, name, strlen (plugin->name))) {
				return plugin->demangle (str);
			}
		}
	}
	return NULL;
}

R_API int r_bin_demangle_type(const char *str) {
	if (str && *str) {
		if (!strcmp (str, "swift")) {
			return R_BIN_NM_SWIFT;
		}
		if (!strcmp (str, "java")) {
			return R_BIN_NM_JAVA;
		}
		if (!strcmp (str, "objc")) {
			return R_BIN_NM_OBJC;
		}
		if (!strcmp (str, "cxx") || !strcmp (str, "c++")) {
			return R_BIN_NM_CXX;
		}
		if (!strcmp (str, "dlang")) {
			return R_BIN_NM_DLANG;
		}
		if (!strcmp (str, "msvc")) {
			return R_BIN_NM_MSVC;
		}
		if (!strcmp (str, "rust")) {
			return R_BIN_NM_RUST;
		}
	}
	return R_BIN_NM_NONE;
}

R_API char *r_bin_demangle(RBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs) {
	int type = -1;
	if (R_STR_ISEMPTY (str)) {
		return NULL;
	}
	RBin *bin = bf? bf->rbin: NULL;
	RBinObject *o = bf? bf->o: NULL;
	RListIter *iter;
	const char *lib = NULL;
	if (!strncmp (str, "reloc.", 6)) {
		str += 6;
	}
	if (!strncmp (str, "sym.", 4)) {
		str += 4;
	}
	if (!strncmp (str, "imp.", 4)) {
		str += 4;
	}
	if (o && libs) {
		bool found = false;
		r_list_foreach (o->libs, iter, lib) {
			size_t len = strlen (lib);
			if (!r_str_ncasecmp (str, lib, len)) {
				str += len;
				if (*str == '_') {
					str++;
				}
				found = true;
				break;
			}
		}
		if (found) {
			size_t len = strlen (bin->file);
			if (!r_str_ncasecmp (str, bin->file, len)) {
				lib = bin->file;
				str += len;
				if (*str == '_') {
					str++;
				}
			}
		}
	}
	if (!strncmp (str, "__", 2)) {
		if (str[2] == 'T') {
			type = R_BIN_NM_SWIFT;
		} else {
			type = R_BIN_NM_CXX;
		//	str++;
		}
	}
	// if str is sym. or imp. when str+=4 str points to the end so just return
	if (!*str) {
		return NULL;
	}
	if (type == -1) {
		type = r_bin_lang_type (bf, def, str);
	}
	char *demangled = NULL;
	switch (type) {
	case R_BIN_NM_JAVA: demangled = r_bin_demangle_java (str); break;
	case R_BIN_NM_RUST: demangled = r_bin_demangle_rust (bf, str, vaddr); break;
	case R_BIN_NM_OBJC: demangled = r_bin_demangle_objc (NULL, str); break;
	case R_BIN_NM_SWIFT: demangled = r_bin_demangle_swift (str, bin? bin->demanglercmd: false); break;
	case R_BIN_NM_CXX: demangled = r_bin_demangle_cxx (bf, str, vaddr); break;
	case R_BIN_NM_MSVC: demangled = r_bin_demangle_msvc (str); break;
	case R_BIN_NM_DLANG: demangled = r_bin_demangle_plugin (bin, "dlang", str); break;
	}
	if (libs && demangled && lib) {
		char *d = r_str_newf ("%s_%s", lib, demangled);
		free (demangled);
		demangled = d;
	}
	return demangled;
}
