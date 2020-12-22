/* radare2 - LGPL - Copyright 2018-2019 - pancake */

#include <r_bin.h>

typedef struct {
	bool rust;
	bool objc;
	bool dlang;
	bool swift;
	bool cxx;
	bool msvc;
} Langs;

static inline bool check_rust(RBinSymbol *sym) {
	return sym->name && strstr (sym->name, "_$LT$");
}

static inline bool check_objc(RBinSymbol *sym) {
	if (sym->name && !strncmp (sym->name, "_OBJC_", 6)) {
		// free (r_bin_demangle_objc (binfile, sym->name));
		return true;
	}
	return false;
}

static bool check_dlang(RBinSymbol *sym) {
	if (!strncmp (sym->name, "_D2", 3)) {
		return true;
	}
	if (!strncmp (sym->name, "_D4", 3)) {
		return true;
	}
	return false;
}

static bool check_swift(RBinSymbol *sym) {
	if (sym->name && strstr (sym->name, "swift_once")) {
		return true;
	}
	return false;
}

static bool check_golang(RBinSymbol *sym) {
	return !strncmp (sym->name, "go.", 3);
}

static inline bool is_cxx_symbol (const char *name) {
	r_return_val_if_fail (name, false);
	if (!strncmp (name, "_Z", 2)) {
		return true;
	}
	if (!strncmp (name, "__Z", 3)) {
		return true;
	}
	return false;
}

static bool check_cxx(RBinSymbol *sym) {
	return is_cxx_symbol (sym->name);
}

static bool check_msvc(RBinSymbol *sym) {
	return *sym->name == '?';
}

/* This is about 10% of the loading time, optimize if possible */
R_API int r_bin_load_languages(RBinFile *binfile) {
	r_return_val_if_fail (binfile, R_BIN_NM_NONE);
	r_return_val_if_fail (binfile->o, R_BIN_NM_NONE);
	r_return_val_if_fail (binfile->o->info, R_BIN_NM_NONE);
	RBinObject *o = binfile->o;
	RBinInfo *info = o->info;
	RBinSymbol *sym;
	RListIter *iter, *iter2;
	Langs cantbe = {0};
	bool phobosIsChecked = false;
	bool swiftIsChecked = false;
	bool canBeCxx = false;
	bool cxxIsChecked = false;
	bool isMsvc = false;

	const char *ft = r_str_get (info->rclass);
	bool unknownType = info->rclass == NULL;
	bool isMacho = strstr (ft, "mach");
	bool isElf = strstr (ft, "elf");
	bool isPe = strstr (ft, "pe");
	bool isBlocks = false;
	bool isObjC = false;

	if (unknownType || !(isMacho || isElf || isPe)) {
		return R_BIN_NM_NONE;
	}

	// check in imports . can be slow
	r_list_foreach (o->imports, iter, sym) {
		const char *name = sym->name;
		if (!strcmp (name, "_NSConcreteGlobalBlock")) {
			isBlocks = true;
		} else if (!strncmp (name, "objc_", 5)) {
			isObjC = true;
			cantbe.objc = true;
		}
	}

	r_list_foreach (o->symbols, iter, sym) {
		char *lib;
		if (!cantbe.rust) {
			if (check_rust (sym)) {
				info->lang = "rust";
				return R_BIN_NM_RUST;
			}
		}
		if (check_golang (sym)) {
			info->lang = "go";
			return R_BIN_NM_GO;
		}
		if (!cantbe.swift) {
			bool hasswift = false;
			if (!swiftIsChecked) {
				r_list_foreach (o->libs, iter2, lib) {
					if (strstr (lib, "swift")) {
						hasswift = true;
						break;
					}
				}
				swiftIsChecked = true;
			}
			if (hasswift || check_swift (sym)) {
				info->lang = "swift";
				return R_BIN_NM_SWIFT;
			}
		}
		if (!cantbe.cxx) {
			bool hascxx = false;
			if (!cxxIsChecked) {
				r_list_foreach (o->libs, iter2, lib) {
					if (strstr (lib, "stdc++") ||
					    strstr (lib, "c++")) {
						hascxx = true;
						break;
					}
					if (strstr (lib, "msvcp")) {
						info->lang = "msvc";
						return R_BIN_NM_MSVC;
					}
				}
				cxxIsChecked = true;
			}
			if (hascxx || check_cxx (sym)) {
				canBeCxx = true;
				cantbe.cxx = true;
			}
		}
		if (!cantbe.objc) {
			if (check_objc (sym)) {
				info->lang = "objc";
				return R_BIN_NM_OBJC;
			}
		}
		if (!cantbe.dlang) {
			bool hasdlang = false;
			if (!phobosIsChecked) {
				r_list_foreach (o->libs, iter2, lib) {
					if (strstr (lib, "phobos")) {
						hasdlang = true;
						break;
					}
				}
				phobosIsChecked = true;
			}
			if (hasdlang || check_dlang (sym)) {
				info->lang = "dlang";
				return R_BIN_NM_DLANG;
			}
		}
		if (!cantbe.msvc) {
			if (!isMsvc && check_msvc (sym)) {
				isMsvc = true;
			}
		}
	}
	if (isObjC) {
		return R_BIN_NM_OBJC | (isBlocks?R_BIN_NM_BLOCKS:0);
	}
	if (canBeCxx) {
		return R_BIN_NM_CXX | (isBlocks?R_BIN_NM_BLOCKS:0);
	}
	if (isMsvc) {
		return R_BIN_NM_MSVC;
	}
	return R_BIN_NM_C | (isBlocks?R_BIN_NM_BLOCKS:0);
}

R_IPI int r_bin_lang_type(RBinFile *binfile, const char *def, const char *sym) {
	int type = 0;
	RBinPlugin *plugin;
	if (sym && sym[0] == sym[1] && sym[0] == '_') {
		type = R_BIN_NM_CXX;
	}
	if (def && *def) {
		type = r_bin_demangle_type (def);
		if (type != R_BIN_NM_NONE) {
			return type;
		}
	}
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->demangle_type) {
		type = plugin->demangle_type (def);
	} else {
		if (binfile && binfile->o && binfile->o->info) {
			type = r_bin_demangle_type (binfile->o->info->lang);
		}
	}
	if (type == R_BIN_NM_NONE) {
		type = r_bin_demangle_type (def);
	}
	return type;
}

R_API const char *r_bin_lang_tostring(int lang) {
	switch (lang & 0xffff) {
	case R_BIN_NM_SWIFT:
		return "swift";
	case R_BIN_NM_GO:
		return "go";
	case R_BIN_NM_JAVA:
		return "java";
	case R_BIN_NM_KOTLIN:
		return "kotlin";
	case R_BIN_NM_C:
		return (lang & R_BIN_NM_BLOCKS)? "c with blocks": "c";
	case R_BIN_NM_CXX:
		return (lang & R_BIN_NM_BLOCKS)? "c++ with blocks": "c++";
	case R_BIN_NM_DLANG:
		return "d";
	case R_BIN_NM_OBJC:
		return (lang & R_BIN_NM_BLOCKS)? "objc with blocks": "objc";
	case R_BIN_NM_MSVC:
		return "msvc";
	case R_BIN_NM_RUST:
		return "rust";
	}
	return NULL;
}

