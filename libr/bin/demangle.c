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

R_API RBinLanguage r_bin_demangle_type(const char *str) {
	RBinLanguage type = r_bin_lang_fromstring (str);
	switch (type) {
	case R_BIN_LANG_JAVA:
	case R_BIN_LANG_CXX:
	case R_BIN_LANG_OBJC:
	case R_BIN_LANG_SWIFT:
	case R_BIN_LANG_DLANG:
	case R_BIN_LANG_MSVC:
	case R_BIN_LANG_RUST:
	case R_BIN_LANG_KOTLIN:
	case R_BIN_LANG_PASCAL:
	case R_BIN_LANG_DART:
	case R_BIN_LANG_GROOVY:
	case R_BIN_LANG_CIL:
	case R_BIN_LANG_IBMXL:
		return type;
	default:
		break;
	}
	if (R_STR_ISNOTEMPTY (str)) {
		if (!strcmp (str, "freepascal")) {
			return R_BIN_LANG_PASCAL;
		}
		if (!strcmp (str, "cxx")) {
			return R_BIN_LANG_CXX;
		}
		if (!strcmp (str, "xlc") || !strcmp (str, "xlc++")) {
			return R_BIN_LANG_IBMXL;
		}
		if (!strcmp (str, "dlang")) {
			return R_BIN_LANG_DLANG;
		}
	}
	return R_BIN_LANG_NONE;
}

static RBinDemanglePlugin *demangle_plugin_by_type(RBin *bin, RBinLanguage type) {
	if (!bin || type <= R_BIN_LANG_NONE || type >= R_BIN_DEMANGLE_TYPE_SLOTS) {
		return NULL;
	}
	return bin->demangle_by_type[type];
}

static char *demangle_without_bin(RBinFile *bf, RBinLanguage type, const char *str, ut64 vaddr) {
	switch (type) {
	case R_BIN_LANG_JAVA: return r_bin_demangle_java (str);
	case R_BIN_LANG_RUST: return r_bin_demangle_rust (bf, str, vaddr);
	case R_BIN_LANG_OBJC: return r_bin_demangle_objc (NULL, str);
	case R_BIN_LANG_SWIFT: return r_bin_demangle_swift (str, false, true);
	case R_BIN_LANG_CXX: return r_bin_demangle_cxx (bf, str, vaddr);
	case R_BIN_LANG_IBMXL: return r_bin_demangle_ibmxl (str);
	case R_BIN_LANG_PASCAL: return r_bin_demangle_freepascal (str);
	case R_BIN_LANG_MSVC: return r_bin_demangle_msvc (str);
	case R_BIN_LANG_DLANG: return r_bin_demangle_dlang (str);
	default: break;
	}
	return NULL;
}

R_API char *r_bin_demangle(RBinFile *bf, const char *def, const char *str, ut64 vaddr, bool libs) {
	RBinLanguage type = R_BIN_LANG_ANY;
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
	if (type == R_BIN_LANG_ANY && r_str_startswith (str, "__")) {
		if (str[2] == 'T') {
			type = R_BIN_LANG_SWIFT;
		} else {
			if (type == R_BIN_LANG_ANY && str[2] == 's') {
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
	if (type == R_BIN_LANG_ANY) {
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
	if (demangled && bf && bf->bo && type > R_BIN_LANG_NONE && type < R_BIN_LANG_LAST) {
		r_bin_file_add_language (bf, type);
	}
	if (libs && demangled && lib) {
		char *d = r_str_newf ("%s_%s", lib, demangled);
		free (demangled);
		demangled = d;
	}
	return demangle_trunc (bf, demangled);
}
