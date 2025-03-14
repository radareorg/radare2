/* radare - LGPL - Copyright 2011-2024 - pancake */

#include <r_bin.h>
#include "i/private.h"
#include <cxx/demangle.h>

R_API void r_bin_demangle_list(RBin *bin) {
	const char *langs[] = {
		"c++",
		"dart",
		"dlang",
		"groovy",
		"java",
		"msvc",
		"objc",
		"pascal",
		"rust",
		"swift",
		NULL
	};
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
			bin->cb_printf ("%s\n", plugin->meta.name);
		}
	}
}

R_API char *r_bin_demangle_plugin(RBin *bin, const char *name, const char *str) {
	RBinPlugin *plugin;
	RListIter *it;
	if (bin && name && str) {
		r_list_foreach (bin->plugins, it, plugin) {
			if (plugin->demangle && !strncmp (plugin->meta.name, name, strlen (plugin->meta.name))) {
				return plugin->demangle (str);
			}
		}
	}
	return NULL;
}

R_API int r_bin_demangle_type(const char *str) {
	if (R_STR_ISNOTEMPTY (str)) {
		if (!strcmp (str, "swift")) {
			return R_BIN_LANG_SWIFT;
		}
		if (!strcmp (str, "java")) {
			return R_BIN_LANG_JAVA;
		}
		if (!strcmp (str, "kotlin")) {
			return R_BIN_LANG_KOTLIN;
		}
		if (!strcmp (str, "groovy")) {
			return R_BIN_LANG_GROOVY;
		}
		if (!strcmp (str, "dart")) {
			return R_BIN_LANG_DART;
		}
		if (!strcmp (str, "objc")) {
			return R_BIN_LANG_OBJC;
		}
		if (!strcmp (str, "pascal") || !strcmp (str, "freepascal")) {
			return R_BIN_LANG_PASCAL;
		}
		if (!strcmp (str, "cxx") || !strcmp (str, "c++")) {
			return R_BIN_LANG_CXX;
		}
		if (!strcmp (str, "dlang")) {
			return R_BIN_LANG_DLANG;
		}
		if (!strcmp (str, "msvc")) {
			return R_BIN_LANG_MSVC;
		}
		if (!strcmp (str, "rust")) {
			return R_BIN_LANG_RUST;
		}
	}
	return R_BIN_LANG_NONE;
}

R_API char *r_bin_demangle(RBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs) {
	int type = -1;
	if (R_STR_ISEMPTY (str)) {
		return NULL;
	}
	RBin *bin = bf? bf->rbin: NULL;
	bool trylib = bin? bin->options.demangle_trylib: true;
	RBinObject *o = bf? bf->bo: NULL;
	RListIter *iter;
	const char *lib = NULL;
	if (r_str_startswith (str, "reloc.")) {
		str += strlen ("reloc.");
	}
	if (r_str_startswith (str, "sym.")) {
		str += strlen ("sym.");
	}
	if (r_str_startswith (str, "imp.")) {
		str += strlen ("imp.");
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
		if (found && bin && bin->file) {
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
	if (r_str_startswith (str, "So") && isdigit (str[2])) {
		char *ss = r_str_newf ("$s%s", str);
		char *res = r_bin_demangle (bf, def, ss, vaddr, libs);
		free (ss);
		return res;
	}
	if (r_str_startswith (str, "_symbolic")) {
		type = R_BIN_LANG_SWIFT;
	}
	if (r_str_startswith (str, "__")) {
		if (str[2] == 'T') {
			type = R_BIN_LANG_SWIFT;
		} else {
			if (type == -1 && str[2] == 's') {
				type = R_BIN_LANG_SWIFT;
			} else {
				type = R_BIN_LANG_CXX;
			}
		}
	}
	// if str is sym. or imp. when str+=4 str points to the end so just return
	if (!*str) {
		return NULL;
	}
	if (type == -1) {
		type = r_bin_lang_type (bf, def, str);
	}
	// type = R_BIN_LANG_SWIFT;
	char *demangled = NULL;
	switch (type) {
	case R_BIN_LANG_JAVA: demangled = r_bin_demangle_java (str); break;
	case R_BIN_LANG_RUST: demangled = r_bin_demangle_rust (bf, str, vaddr); break;
	case R_BIN_LANG_OBJC: demangled = r_bin_demangle_objc (NULL, str); break;
	case R_BIN_LANG_SWIFT: demangled = r_bin_demangle_swift (str, bin? bin->options.demangle_usecmd: false, trylib); break;
	case R_BIN_LANG_CXX: demangled = r_bin_demangle_cxx (bf, str, vaddr); break;
	case R_BIN_LANG_PASCAL: demangled = r_bin_demangle_freepascal (str); break;
	case R_BIN_LANG_MSVC: demangled = r_bin_demangle_msvc (str); break;
	case R_BIN_LANG_DLANG: demangled = r_bin_demangle_plugin (bin, "dlang", str); break;
	}
	if (libs && demangled && lib) {
		char *d = r_str_newf ("%s_%s", lib, demangled);
		free (demangled);
		demangled = d;
	}
	return demangled;
}
