/* radare2 - LGPL - Copyright 2018-2023 - pancake */

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
	if (r_str_startswith (sym->name, "_D2")) {
		return true;
	}
	if (r_str_startswith (sym->name, "_D4")) {
		return true;
	}
	return false;
}

static bool check_swift(RBinSymbol *sym) {
	return (sym->name && strstr (sym->name, "swift_once"));
}

static bool check_golang(RBinSymbol *sym) {
	return !strncmp (sym->name, "go.", 3);
}

static inline bool is_cxx_symbol(const char *name) {
	r_return_val_if_fail (name, false);
	if (r_str_startswith (name, "_Z")) {
		return true;
	}
	if (r_str_startswith (name, "__Z")) {
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

static inline bool check_kotlin(RBinSymbol *sym) {
	return sym->name && strstr (sym->name, "kotlin_");
}
static inline bool check_groovy(RBinSymbol *sym) {
	return strstr (sym->name, "_groovy");
}
static inline bool check_dart(RBinSymbol *sym) {
	return strstr (sym->name, "io_flutter_");
}

static inline bool check_pascal(RBinSymbol *sym) {
	if (strstr (sym->name, "$_$")) {
		return true;
	}
	return strstr (sym->name, "_$$_");
}

/* This is about 10% of the loading time, optimize if possible */
R_API int r_bin_load_languages(RBinFile *binfile) {
	r_return_val_if_fail (binfile, R_BIN_LANG_NONE);
	r_return_val_if_fail (binfile->o, R_BIN_LANG_NONE);
	r_return_val_if_fail (binfile->o->info, R_BIN_LANG_NONE);
	RBinObject *o = binfile->o;
	RBinInfo *info = o->info;
	RBinSymbol *sym = NULL;
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
		return R_BIN_LANG_NONE;
	}

	// check in imports . can be slow
	r_list_foreach (o->imports, iter, sym) {
		const char *name = sym->name;
		if (!strcmp (name, "_NSConcreteGlobalBlock")) {
			isBlocks = true;
		} else if (r_str_startswith (name, "objc_")) {
			isObjC = true;
			cantbe.objc = true;
		}
	}

	r_list_foreach (o->symbols, iter, sym) {
		char *lib;
		if (!cantbe.rust) {
			if (check_rust (sym)) {
				info->lang = "rust";
				return R_BIN_LANG_RUST;
			}
		}
		if (check_golang (sym)) {
			info->lang = "go";
			return R_BIN_LANG_GO;
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
				return R_BIN_LANG_SWIFT;
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
						return R_BIN_LANG_MSVC;
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
				return R_BIN_LANG_OBJC;
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
				return R_BIN_LANG_DLANG;
			}
		}
		if (!cantbe.msvc) {
			if (!isMsvc && check_msvc (sym)) {
				isMsvc = true;
			}
		}
	}
	if (isObjC) {
		return R_BIN_LANG_OBJC | (isBlocks?R_BIN_LANG_BLOCKS:0);
	}
	if (sym) {
		if (check_kotlin (sym)) {
			info->lang = "kotlin";
			return R_BIN_LANG_KOTLIN;
		}
		if (check_groovy (sym)) {
			info->lang = "groovy";
			return R_BIN_LANG_GROOVY;
		}
		if (check_dart (sym)) {
 			info->lang = "dart";
 			return R_BIN_LANG_DART;
 		}
		if (check_pascal (sym)) {
 			info->lang = "pascal";
 			return R_BIN_LANG_PASCAL;
 		}
	}
	if (canBeCxx) {
		return R_BIN_LANG_CXX | (isBlocks? R_BIN_LANG_BLOCKS: 0);
	}
	if (isMsvc) {
		return R_BIN_LANG_MSVC;
	}
	return R_BIN_LANG_C | (isBlocks? R_BIN_LANG_BLOCKS: 0);
}

// if its ipi no need to be prefixed with r_
R_IPI int r_bin_lang_type(RBinFile *binfile, const char *def, const char *sym) {
	int type = R_BIN_LANG_NONE;
	if (sym) {
		if (r_str_startswith (sym, "__")) {
			type = R_BIN_LANG_CXX;
		}
		if (r_str_startswith (sym, "_Z")) {
			return R_BIN_LANG_RUST;
		}
	}
	if (R_STR_ISNOTEMPTY (def)) {
		type = r_bin_demangle_type (def);
		if (type != R_BIN_LANG_NONE) {
			return type;
		}
	}
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (def && plugin && plugin->demangle_type) {
		type = plugin->demangle_type (def);
	} else if (binfile && binfile->o && binfile->o->info) {
		type = r_bin_demangle_type (binfile->o->info->lang);
	}
	if (def && type == R_BIN_LANG_NONE) {
		type = r_bin_demangle_type (def);
	}
	return type;
}

R_API const char *r_bin_lang_tostring(int lang) {
	switch (lang & 0xffff) {
	case R_BIN_LANG_SWIFT:
		return "swift";
	case R_BIN_LANG_GO:
		return "go";
	case R_BIN_LANG_JAVA:
		return "java";
	case R_BIN_LANG_KOTLIN:
		return "kotlin";
	case R_BIN_LANG_DART:
		return "dart";
	case R_BIN_LANG_GROOVY:
		return "groovy";
	case R_BIN_LANG_JNI:
		return "jni";
	case R_BIN_LANG_C:
		return (lang & R_BIN_LANG_BLOCKS)? "c with blocks": "c";
	case R_BIN_LANG_CXX:
		return (lang & R_BIN_LANG_BLOCKS)? "c++ with blocks": "c++";
	case R_BIN_LANG_DLANG:
		return "d";
	case R_BIN_LANG_OBJC:
		return (lang & R_BIN_LANG_BLOCKS)? "objc with blocks": "objc";
	case R_BIN_LANG_MSVC:
		return "msvc";
	case R_BIN_LANG_RUST:
		return "rust";
	}
	return "?";
}
