/* radare2 - LGPL - Copyright 2018 - pancake */

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

static bool check_cxx(RBinSymbol *sym) {
	if (!strncmp (sym->name, "_Z", 2)) {
		return true;
	}
	if (!strncmp (sym->name, "__Z", 3)) {
		return true;
	}
	return false;
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

	char *ft = info->rclass? info->rclass: "";
	bool unknownType = info->rclass == NULL;
	bool isMacho = strstr (ft, "mach");
	bool isElf = strstr (ft, "elf");
	bool isPe = strstr (ft, "pe");

	r_list_foreach (o->symbols, iter, sym) {
		char *lib;
		if (!cantbe.rust) {
			if (check_rust (sym)) {
				info->lang = "rust";
				return R_BIN_NM_RUST;
			}
		}
		if (!cantbe.swift) {
			bool hasswift = false;
			if (unknownType || !(isMacho || isElf)) {
				cantbe.swift = false;
				continue;
			}
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
			if (unknownType || !(isMacho || isElf)) {
				cantbe.swift = false;
				continue;
			}
			if (!cxxIsChecked) {
				r_list_foreach (o->libs, iter2, lib) {
					if (strstr (lib, "stdc++") ||
					    strstr (lib, "c++")) {
						hascxx = true;
						break;
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
			if (unknownType || !(isMacho || isElf)) {
				cantbe.objc = true;
				continue;
			}
			if (check_objc (sym)) {
				info->lang = "objc";
				return R_BIN_NM_OBJC;
			}
		}
		if (!cantbe.dlang) {
			bool hasdlang = false;
			if (unknownType && !(isMacho || isElf || isPe)) {
				cantbe.dlang = true;
				continue;
			}
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
	if (canBeCxx) {
		info->lang = "c++";
		return R_BIN_NM_CXX;
	}
	if (isMsvc) {
		return R_BIN_NM_MSVC;
	}
	return R_BIN_NM_NONE;
}

R_API int r_bin_lang_type(RBinFile *binfile, const char *def, const char *sym) {
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

