/* radare2 - LGPL - Copyright 2018-2024 - pancake */

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
	const char *oname = r_bin_name_tostring2 (sym->name, 'o');
	return oname && strstr (oname, "_$LT$");
}

static inline bool check_objc(RBinSymbol *sym) {
	const char *sym_name = r_bin_name_tostring2 (sym->name, 'o');
	return (sym_name && r_str_startswith (sym_name, "_OBJC_"));
}

static bool check_dlang(RBinSymbol *sym) {
	const char *name = r_bin_name_tostring2 (sym->name, 'o');
	if (r_str_startswith (name, "_D")) {
		return isdigit (name[2]);
	}
	return false;
}

static bool check_swift(RBinSymbol *sym) {
	const char *sym_name = r_bin_name_tostring2 (sym->name, 'o');
	return (sym_name && strstr (sym_name, "swift_once"));
}

static bool check_golang(RBinSymbol *sym) {
	const char *sym_name = r_bin_name_tostring (sym->name);
	return r_str_startswith (sym_name, "go:");
}

static inline bool is_cxx_symbol(const char *name) {
	R_RETURN_VAL_IF_FAIL (name, false);
	if (*name == '_') {
		name++;
		if (*name == '_') {
			name++;
		}
		return *name == 'Z';
	}
	return false;
}

static bool check_cxx(RBinSymbol *sym) {
	const char *sym_name = r_bin_name_tostring2 (sym->name, 'o');
	return is_cxx_symbol (sym_name);
}

static bool check_msvc(RBinSymbol *sym) {
	const char *oname = r_bin_name_tostring2 (sym->name, 'o');
	return *oname == '?';
}

static inline bool check_kotlin(RBinSymbol *sym) {
	const char *name = r_bin_name_tostring2 (sym->name, 'o');
	return name && strstr (name, "kotlin_");
}
static inline bool check_groovy(RBinSymbol *sym) {
	const char *name = r_bin_name_tostring2 (sym->name, 'o');
	return strstr (name, "_groovy");
}
static inline bool check_dart(RBinSymbol *sym) {
	const char *name = r_bin_name_tostring2 (sym->name, 'o');
	return strstr (name, "io_flutter_");
}

static inline bool check_pascal(RBinSymbol *sym) {
	const char *name = r_bin_name_tostring2 (sym->name, 'o');
	if (strstr (name, "$_$")) {
		return true;
	}
	return strstr (name, "_$$_");
}

typedef struct {
	Langs cantbe;
	bool phobosIsChecked;
	bool swiftIsChecked;
	bool canBeCxx;
	bool cxxIsChecked;
	bool isMsvc;
	bool isBlocks;
	bool isObjC;
} LangCheck;

static bool check_symbol_lang(RBinFile *bf, LangCheck *lc, RBinSymbol *sym, int *type) {
	RBinObject *bo = bf->bo;
	RBinInfo *info = bo->info;
	char *lib;
	if (!lc->cantbe.rust) {
		if (check_rust (sym)) {
			info->lang = "rust";
			*type = R_BIN_LANG_RUST;
			return false;
		}
	}
	if (check_golang (sym)) {
		info->lang = "go";
		*type = R_BIN_LANG_GO;
		return false;
	}
	if (!lc->cantbe.swift) {
		bool hasswift = false;
		if (!lc->swiftIsChecked) {
			RListIter *iter;
			r_list_foreach (bo->libs, iter, lib) {
				if (strstr (lib, "swift")) {
					hasswift = true;
					break;
				}
			}
			lc->swiftIsChecked = true;
		}
		if (hasswift || check_swift (sym)) {
			info->lang = "swift";
			*type = R_BIN_LANG_SWIFT;
			return false;
		}
	}
	if (!lc->cantbe.cxx) {
		bool hascxx = false;
		if (!lc->cxxIsChecked) {
			RListIter *iter;
			r_list_foreach (bo->libs, iter, lib) {
				if (strstr (lib, "stdc++") || strstr (lib, "c++")) {
					hascxx = true;
					break;
				}
				if (strstr (lib, "msvcp")) {
					info->lang = "msvc";
					*type = R_BIN_LANG_MSVC;
					return false;
				}
			}
			lc->cxxIsChecked = true;
		}
		if (hascxx || check_cxx (sym)) {
			lc->canBeCxx = true; // wtf?
			lc->cantbe.cxx = true; // should be false?
		}
	}
	if (!lc->cantbe.objc) {
		if (check_objc (sym)) {
			info->lang = "objc";
			*type = R_BIN_LANG_OBJC;
			return false;
		}
	}
	if (!lc->cantbe.dlang) {
		bool hasdlang = false;
		if (!lc->phobosIsChecked) {
			RListIter *iter;
			r_list_foreach (bo->libs, iter, lib) {
				if (strstr (lib, "phobos")) {
					hasdlang = true;
					break;
				}
			}
			lc->phobosIsChecked = true;
		}
		if (hasdlang || check_dlang (sym)) {
			info->lang = "dlang";
			*type = R_BIN_LANG_DLANG;
			return false;
		}
	}
	if (!lc->cantbe.msvc) {
		if (!lc->isMsvc && check_msvc (sym)) {
			lc->isMsvc = true;
			lc->cantbe.msvc = true;
		}
	}
	if (!lc->cantbe.cxx) {
		if (check_kotlin (sym)) {
			info->lang = "kotlin";
			*type = R_BIN_LANG_KOTLIN;
			return false;
		}
		if (check_groovy (sym)) {
			info->lang = "groovy";
			*type = R_BIN_LANG_GROOVY;
			return false;
		}
		if (check_dart (sym)) {
			info->lang = "dart";
			*type = R_BIN_LANG_DART;
			return false;
		}
		if (check_pascal (sym)) {
			info->lang = "pascal";
			*type = R_BIN_LANG_PASCAL;
			return false;
		}
	}
	return true;
}

/* This is about 10% of the loading time, optimize checking when registering the symbols */
R_API int r_bin_load_languages(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->info, R_BIN_LANG_NONE);
	RBinObject *bo = bf->bo;
	RBinInfo *info = bo->info;
	RBinSymbol *sym = NULL;
	RListIter *iter;
	LangCheck lc = {0};
	const char *ft = r_str_get (info->rclass);
	const bool unknownType = info->rclass == NULL;
	const bool isMacho = strstr (ft, "mach");
	const bool isElf = strstr (ft, "elf");
	const bool isPe = strstr (ft, "pe");

	if (unknownType || !(isMacho || isElf || isPe)) {
		return R_BIN_LANG_NONE;
	}
	RBinImport *imp;
	if (bo->imports) {
		// R2_600 deprecate when all plugins use the imports vec
		r_list_foreach (bo->imports, iter, imp) {
			const char *name = r_bin_name_tostring2 (imp->name, 'o');
			if (!strcmp (name, "_NSConcreteGlobalBlock")) {
				lc.isBlocks = true;
			} else if (r_str_startswith (name, "objc_")) {
				lc.isObjC = true;
				lc.cantbe.objc = true;
			}
		}
	} else {
		R_VEC_FOREACH (&bo->imports_vec, imp) {
			const char *name = r_bin_name_tostring2 (imp->name, 'o');
			if (!strcmp (name, "_NSConcreteGlobalBlock")) {
				lc.isBlocks = true;
			} else if (r_str_startswith (name, "objc_")) {
				lc.isObjC = true;
				lc.cantbe.objc = true;
			}
		}
	}
	int type = -1;
	if (bo->symbols) {
		// deprecate
		r_list_foreach (bo->symbols, iter, sym) {
			if (!check_symbol_lang (bf, &lc, sym, &type)) {
				break;
			}
		}
	} else {
		R_VEC_FOREACH (&bo->symbols_vec, sym) {
			if (!check_symbol_lang (bf, &lc, sym, &type)) {
				break;
			}
		}
	}
	if (type != -1) {
		return type;
	}
	if (lc.isObjC) {
		return R_BIN_LANG_OBJC | (lc.isBlocks?R_BIN_LANG_BLOCKS:0);
	}
	if (lc.canBeCxx) {
		return R_BIN_LANG_CXX | (lc.isBlocks? R_BIN_LANG_BLOCKS: 0);
	}
	if (lc.isMsvc) {
		return R_BIN_LANG_MSVC;
	}
	return R_BIN_LANG_C | (lc.isBlocks? R_BIN_LANG_BLOCKS: 0);
}

// if its ipi no need to be prefixed with r_
R_IPI int r_bin_lang_type(R_NULLABLE RBinFile *bf, R_NULLABLE const char *def, R_NULLABLE const char *sym) {
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
	if (bf) {
		RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
		if (def && plugin && plugin->demangle_type) {
			type = plugin->demangle_type (def);
		} else if (bf->bo && bf->bo->info) {
			type = r_bin_demangle_type (bf->bo->info->lang);
		}
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
