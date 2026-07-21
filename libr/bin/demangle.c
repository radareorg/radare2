/* radare - LGPL - Copyright 2011-2024 - pancake */

#include <r_bin.h>
#include "i/private.h"

static char *demangle_trunc(RBinFile *bf, char *s) {
	RBin *bin = bf? bf->rbin: NULL;
	const int maxsymlen = bin? bin->options.maxsymlen: 0;
	if (s && maxsymlen > 0) {
		const size_t slen = strlen (s);
		if (slen > (size_t)maxsymlen) {
			char *ns = r_str_ndup (s, maxsymlen);
			if (ns) {
				if (maxsymlen > 3) {
					ns[maxsymlen - 3] = '.';
					ns[maxsymlen - 2] = '.';
					ns[maxsymlen - 1] = '.';
				}
				free (s);
				return ns;
			}
		}
	}
	return s;
}

R_API void r_bin_demangle_list(RBin *bin) {
	if (!bin) {
		return;
	}
	RBinDemanglePlugin *plugin;
	RListIter *iter;
	r_list_foreach (bin->demangle_plugins, iter, plugin) {
		bin->cb_printf ("%s\n", plugin->meta.name);
	}
}

static char *demangle_legacy_plugin(RBin *bin, const char *name, const char *str) {
	RBinPlugin *plugin;
	RListIter *it;
	if (bin && name && str) {
		RList *plugins = bin->libstore->plugins;
		r_list_foreach (plugins, it, plugin) {
			if (plugin->demangle && !strncmp (plugin->meta.name, name, strlen (plugin->meta.name))) {
				return plugin->demangle (str);
			}
		}
	}
	return NULL;
}

R_API char *r_bin_demangle_plugin(RBin *bin, const char *name, const char *str) {
	R_RETURN_VAL_IF_FAIL (bin && name && str, NULL);
	RBinDemanglePlugin *plugin = r_bin_demangle_plugin_find (bin, name);
	if (plugin) {
		RBinFile *bf = bin->cur;
		RBinFile tmp = { 0 };
		if (!bf && plugin->type == R_BIN_LANG_SWIFT) {
			tmp.rbin = bin;
			bf = &tmp;
		}
		char *res = plugin->demangle (bf, str, 0);
		if (res) {
			return res;
		}
	}
	return demangle_legacy_plugin (bin, name, str);
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
		if (!strcmp (str, "ibmxl") || !strcmp (str, "xlc") || !strcmp (str, "xlc++")) {
			return R_BIN_LANG_IBMXL;
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
		if (!strcmp (str, "cil")) {
			return R_BIN_LANG_CIL;
		}
	}
	return R_BIN_LANG_NONE;
}

static RBinDemanglePlugin *demangle_plugin_by_type(RBin *bin, int type) {
	ut32 value = (ut32)type & 0xffff;
	if (!bin || !value || (value & (value - 1))) {
		return NULL;
	}
	int index = r_bits_ctz32 (value);
	return index < R_BIN_DEMANGLE_TYPE_SLOTS? bin->demangle_by_type[index]: NULL;
}

static char *demangle_without_bin(RBinFile *bf, int type, const char *str, ut64 vaddr) {
	switch (type & 0xffff) {
	case R_BIN_LANG_JAVA: return r_bin_demangle_java (str);
	case R_BIN_LANG_RUST: return r_bin_demangle_rust (bf, str, vaddr);
	case R_BIN_LANG_OBJC: return r_bin_demangle_objc (NULL, str);
	case R_BIN_LANG_SWIFT: return r_bin_demangle_swift (str, false, true);
	case R_BIN_LANG_CXX: return r_bin_demangle_cxx (bf, str, vaddr);
	case R_BIN_LANG_IBMXL: return r_bin_demangle_ibmxl (str);
	case R_BIN_LANG_PASCAL: return r_bin_demangle_freepascal (str);
	case R_BIN_LANG_MSVC: return r_bin_demangle_msvc (str);
	case R_BIN_LANG_DLANG: return r_bin_demangle_dlang (str);
	}
	return NULL;
}

R_API char *r_bin_demangle(RBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs) {
	int type = -1;
	if (R_STR_ISEMPTY (str)) {
		return NULL;
	}
	RBin *bin = bf? bf->rbin: NULL;
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
	if (r_bin_lang_rustv0 (str)) {
		type = R_BIN_LANG_RUST;
	}
	if (type == -1 && r_str_startswith (str, "__")) {
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
	char *demangled = NULL;
	if (bin) {
		RBinDemanglePlugin *plugin = demangle_plugin_by_type (bin, type);
		if (!plugin && R_STR_ISNOTEMPTY (def)) {
			plugin = r_bin_demangle_plugin_find (bin, def);
		}
		if (plugin) {
			demangled = plugin->demangle (bf, str, vaddr);
		}
		if (!demangled && type == R_BIN_LANG_DLANG) {
			demangled = demangle_legacy_plugin (bin, "dlang", str);
		}
	} else {
		demangled = demangle_without_bin (bf, type, str, vaddr);
	}
	if (libs && demangled && lib) {
		char *d = r_str_newf ("%s_%s", lib, demangled);
		free (demangled);
		demangled = d;
	}
	return demangle_trunc (bf, demangled);
}
