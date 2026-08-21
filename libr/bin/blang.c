/* radare2 - LGPL - Copyright 2018-2024 - pancake */

#include <r_bin.h>

// Rust v0 (RFC 2603) symbols: "_R" or "__R", optional decimal version, then a
// path production, which always starts with one of C M X Y N I B.
R_IPI bool r_bin_lang_rustv0(const char *name) {
	if (R_STR_ISEMPTY (name) || *name != '_') {
		return false;
	}
	name++;
	if (*name == '_') {
		name++;
	}
	if (*name != 'R') {
		return false;
	}
	name++;
	while (isdigit ((unsigned char)*name)) {
		name++;
	}
	return *name && strchr ("CMXYNIB", *name);
}

static inline bool is_rust_symbol(const char *name) {
	return name && (strstr (name, "_$LT$") || r_bin_lang_rustv0 (name));
}

static inline bool is_objc_symbol(const char *name) {
	return name && r_str_startswith (name, "_OBJC_");
}

static inline bool is_jni_symbol(const char *name) {
	return name && (r_str_startswith (name, "Java_")
		|| !strcmp (name, "JNI_OnLoad")
		|| !strcmp (name, "JNI_OnUnload"));
}

static bool is_dlang_symbol(const char *name) {
	if (name && r_str_startswith (name, "__D")) {
		name++;
	}
	if (name && r_str_startswith (name, "_D")) {
		return isdigit (name[2]);
	}
	return false;
}

static bool is_swift_symbol(const char *name) {
	return name && (strstr (name, "swift_once")
		|| r_str_startswith (name, "$s") || r_str_startswith (name, "_$s"));
}

static bool is_golang_symbol(const char *name) {
	return name && r_str_startswith (name, "go:");
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

static inline bool is_ibmxl_symbol(const char *name) {
	R_RETURN_VAL_IF_FAIL (name, false);
	const char *symbol = name;
	if (*name == '.') {
		name++;
	}
	if (*name == '?' || r_str_startswith (name, "_Z") || r_str_startswith (name, "__Z")) {
		return false;
	}
	bool candidate = r_str_startswith (name, "__ct__")
		|| r_str_startswith (name, "__dt__") || r_str_startswith (name, "__vft");
	if (!candidate && name[0] == '_' && name[1] == '_') {
		const char *sep = strstr (name + 2, "__");
		if (!sep || sep == name + 2 || !islower ((unsigned char)name[2])) {
			return false;
		}
		char ch = sep[2];
		candidate = ch == 'F' || ch == 'H' || ch == 'C' || ch == 'V'
			|| ch == 'Q' || isdigit ((unsigned char)ch);
	} else if (!candidate) {
		const char *sep = strstr (name, "__");
		if (!sep || sep == name) {
			return false;
		}
		char ch = sep[2];
		candidate = ch == 'F' || ch == 'H' || ch == 'C' || ch == 'V'
			|| ch == 'Q' || isdigit ((unsigned char)ch);
	}
	if (!candidate) {
		return false;
	}
	char *demangled = r_bin_demangle_ibmxl (symbol);
	bool valid = demangled != NULL;
	free (demangled);
	return valid;
}

static bool is_msvc_symbol(const char *name) {
	if (!name || *name != '?') {
		return false;
	}
	char *demangled = r_bin_demangle_msvc (name);
	bool valid = demangled != NULL;
	free (demangled);
	return valid;
}

static inline bool is_kotlin_symbol(const char *name) {
	return name && strstr (name, "kotlin_");
}
static inline bool is_groovy_symbol(const char *name) {
	return name && strstr (name, "_groovy");
}
static inline bool is_dart_symbol(const char *name) {
	return name && strstr (name, "io_flutter_");
}

static inline bool is_pascal_symbol(const char *name) {
	if (name && strstr (name, "$_$")) {
		return true;
	}
	return name && strstr (name, "_$$_");
}

R_IPI RBinLanguage r_bin_lang_from_symbol_name(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return R_BIN_LANG_NONE;
	}
	if (is_rust_symbol (name)) {
		return R_BIN_LANG_RUST;
	}
	if (is_golang_symbol (name)) {
		return R_BIN_LANG_GO;
	}
	if (is_swift_symbol (name)) {
		return R_BIN_LANG_SWIFT;
	}
	if (is_objc_symbol (name)) {
		return R_BIN_LANG_OBJC;
	}
	if (is_jni_symbol (name)) {
		return R_BIN_LANG_JNI;
	}
	if (is_dlang_symbol (name)) {
		return R_BIN_LANG_DLANG;
	}
	if (is_kotlin_symbol (name)) {
		return R_BIN_LANG_KOTLIN;
	}
	if (is_groovy_symbol (name)) {
		return R_BIN_LANG_GROOVY;
	}
	if (is_dart_symbol (name)) {
		return R_BIN_LANG_DART;
	}
	if (is_pascal_symbol (name)) {
		return R_BIN_LANG_PASCAL;
	}
	if (is_ibmxl_symbol (name)) {
		return R_BIN_LANG_IBMXL;
	}
	if (is_cxx_symbol (name)) {
		return R_BIN_LANG_CXX;
	}
	return is_msvc_symbol (name)? R_BIN_LANG_MSVC: R_BIN_LANG_NONE;
}

R_API void r_bin_file_add_language(RBinFile *bf, RBinLanguage lang) {
	R_RETURN_IF_FAIL (bf && bf->bo);
	if (lang > R_BIN_LANG_NONE && lang < R_BIN_LANG_LAST) {
		bf->bo->langs = r_vpack_add (bf->bo->langs, lang);
	}
}

R_IPI void r_bin_register_symbol_language(RBinFile *bf, RBinSymbol *sym) {
	R_RETURN_IF_FAIL (sym);
	RBinLanguage lang = sym->attr.lang;
	if (lang == R_BIN_LANG_NONE && sym->name) {
		lang = r_bin_lang_from_symbol_name (r_bin_name_tostring2 (sym->name, 'o'));
		sym->attr.lang = lang;
	}
	if (bf && bf->bo && lang != R_BIN_LANG_NONE) {
		r_bin_file_add_language (bf, lang);
	}
}

static RBinLanguage preferred_language(RBinLanguages langs) {
	RBinLanguage first = R_BIN_LANG_NONE;
	while (langs) {
		RBinLanguage lang = R_VPACK_FIRST (langs);
		if (first == R_BIN_LANG_NONE && lang != R_BIN_LANG_C
				&& lang != R_BIN_LANG_C_BLOCKS) {
			first = lang;
		}
		if (lang != R_BIN_LANG_C && lang != R_BIN_LANG_C_BLOCKS
				&& lang != R_BIN_LANG_CXX && lang != R_BIN_LANG_CXX_BLOCKS
				&& lang != R_BIN_LANG_MSVC && lang != R_BIN_LANG_IBMXL) {
			return lang;
		}
		langs >>= R_VPACK_SIZE;
	}
	return first;
}

static RBinLanguage declared_language(const char *name) {
	RBinLanguage lang = r_bin_lang_fromstring (name);
	if (lang == R_BIN_LANG_NONE && name && (!strcmp (name, "dalvik")
			|| r_str_startswith (name, "java "))) {
		lang = R_BIN_LANG_JAVA;
	}
	if (lang == R_BIN_LANG_NONE) {
		lang = r_bin_demangle_type (name);
	}
	return lang;
}

typedef struct {
	bool blocks;
	bool objc;
} RBinLanguageHints;

static RBinLanguageHints language_hints(RBinObject *bo) {
	RBinLanguageHints hints = {0};
	RBinImport *imp;
	R_VEC_FOREACH (&bo->imports_vec, imp) {
		const char *name = r_bin_name_tostring2 (imp->name, 'o');
		if (name && !strcmp (name, "_NSConcreteGlobalBlock")) {
			hints.blocks = true;
		} else if (name && (r_str_startswith (name, "objc_")
				|| r_str_startswith (name, "_objc_"))) {
			hints.objc = true;
		}
	}
	return hints;
}

static void register_library_languages(RBinFile *bf) {
	RListIter *iter;
	const char *lib;
	r_list_foreach (bf->bo->libs, iter, lib) {
		if (R_STR_ISEMPTY (lib)) {
			continue;
		}
		if (strstr (lib, "swift")) {
			r_bin_file_add_language (bf, R_BIN_LANG_SWIFT);
		}
		if (strstr (lib, "msvcp")) {
			r_bin_file_add_language (bf, R_BIN_LANG_MSVC);
		} else if (strstr (lib, "stdc++") || strstr (lib, "c++")) {
			r_bin_file_add_language (bf, R_BIN_LANG_CXX);
		}
		if (strstr (lib, "phobos")) {
			r_bin_file_add_language (bf, R_BIN_LANG_DLANG);
		}
	}
}

static RBinLanguage primary_language(RBinLanguages langs, RBinLanguage declared, RBinLanguageHints hints) {
	RBinLanguage primary = declared;
	if (R_VPACK_HAS (langs, R_BIN_LANG_JNI)) {
		primary = R_BIN_LANG_JNI;
	} else if (hints.objc && primary != R_BIN_LANG_SWIFT) {
		primary = hints.blocks? R_BIN_LANG_OBJC_BLOCKS: R_BIN_LANG_OBJC;
	} else if (primary == R_BIN_LANG_NONE || primary == R_BIN_LANG_C
			|| primary == R_BIN_LANG_C_BLOCKS) {
		RBinLanguage preferred = preferred_language (langs);
		if (preferred != R_BIN_LANG_NONE) {
			primary = preferred;
		}
	}
	if (primary == R_BIN_LANG_NONE) {
		primary = R_BIN_LANG_C;
	}
	if (hints.blocks) {
		if (primary == R_BIN_LANG_C || primary == R_BIN_LANG_C_BLOCKS) {
			primary = R_BIN_LANG_C_BLOCKS;
		} else if (primary == R_BIN_LANG_CXX || primary == R_BIN_LANG_IBMXL
				|| primary == R_BIN_LANG_CXX_BLOCKS) {
			primary = R_BIN_LANG_CXX_BLOCKS;
		}
	}
	return primary;
}

R_API RBinLanguages r_bin_load_languages(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->info, R_BIN_LANG_NONE);
	RBinObject *bo = bf->bo;
	RBinInfo *info = bo->info;
	RBinLanguage declared = declared_language (info->lang);
	if (declared != R_BIN_LANG_NONE) {
		r_bin_file_add_language (bf, declared);
	}
	const char *rclass = info->rclass;
	if (!rclass || (!strstr (rclass, "mach")
			&& !strstr (rclass, "elf") && !strstr (rclass, "pe"))) {
		return bo->langs;
	}

	RBinLanguageHints hints = language_hints (bo);
	register_library_languages (bf);
	RBinLanguage primary = primary_language (bo->langs, declared, hints);
	r_bin_file_add_language (bf, primary);
	if (!info->lang || !strcmp (info->lang, "?") || hints.objc
			|| primary == R_BIN_LANG_JNI
			|| ((declared == R_BIN_LANG_C || declared == R_BIN_LANG_C_BLOCKS)
				&& primary != declared)) {
		info->lang = r_bin_lang_tostring (primary);
	}
	return bo->langs;
}

// if its ipi no need to be prefixed with r_
R_IPI RBinLanguage r_bin_lang_type(RBinFile * R_NULLABLE bf, const char * R_NULLABLE def, const char * R_NULLABLE sym) {
	RBinLanguage type = R_BIN_LANG_NONE;
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
	if (type != R_BIN_LANG_NONE || !sym) {
		return type;
	}
	if (is_ibmxl_symbol (sym)) {
		return R_BIN_LANG_IBMXL;
	}
	if (r_bin_lang_rustv0 (sym)) {
		return R_BIN_LANG_RUST;
	}
	if (r_str_startswith (sym, "__")) {
		return R_BIN_LANG_CXX;
	}
	return r_str_startswith (sym, "_Z")? R_BIN_LANG_RUST: R_BIN_LANG_NONE;
}

static const char *const lang_names[] = {
	"?", "java", "c", "go", "c++", "objc", "swift", "d",
	"msvc", "rust", "kotlin", "pascal", "dart", "groovy", "jni", "cil", "ibmxl",
	"c with blocks", "c++ with blocks", "objc with blocks"
};

R_API RBinLanguage r_bin_lang_fromstring(const char *name) {
	RBinLanguage i;
	for (i = R_BIN_LANG_JAVA; R_STR_ISNOTEMPTY (name) && i < R_BIN_LANG_LAST; i++) {
		if (!strcmp (lang_names[i], name)) {
			return i;
		}
	}
	return R_BIN_LANG_NONE;
}

R_API const char *r_bin_lang_tostring(RBinLanguage lang) {
	return lang >= R_BIN_LANG_NONE && lang < R_BIN_LANG_LAST? lang_names[lang]: "?";
}
