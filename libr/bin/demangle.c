/* radare - LGPL - Copyright 2011-2018 - pancake */

#include <r_bin.h>
#include <cxx/demangle.h>

R_API void r_bin_demangle_list(RBin *bin) {
	const char *langs[] = { "c++", "java", "objc", "swift", "dlang", "msvc", NULL };
	RBinPlugin *plugin;
	RListIter *it;
	int i;
	if (!bin) {
		return;
	}
	for (i = 0; langs[i]; i++) {
		eprintf ("%s\n", langs[i]);
	}
	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->demangle) {
			eprintf ("%s\n", plugin->name);
		}
	}
}

R_API char *r_bin_demangle_plugin(RBin *bin, const char *name, const char *str) {
	RBinPlugin *plugin;
	RListIter *it;
	if (bin && name && str) {
		r_list_foreach (bin->plugins, it, plugin) {
			if (plugin->demangle) {
				return plugin->demangle (str);
			}
		}
	}
	return NULL;
}

R_API const char *r_bin_lang_tostring (int lang) {
	switch (lang) {
	case R_BIN_NM_SWIFT:
		return "swift";
	case R_BIN_NM_JAVA:
		return "java";
	case R_BIN_NM_CXX:
		return "c++";
	case R_BIN_NM_DLANG:
		return "d";
	case R_BIN_NM_OBJC:
		return "objc";
	case R_BIN_NM_MSVC:
		return "msvc";
	case R_BIN_NM_RUST:
		return "rust";
	}
	return NULL;
}

R_API int r_bin_demangle_type (const char *str) {
	if (!str || !*str) {
		return R_BIN_NM_NONE;
	}
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
	return R_BIN_NM_NONE;
}

R_API char *r_bin_demangle(RBinFile *binfile, const char *def, const char *str, ut64 vaddr) {
	int type = -1;
	if (!str || !*str) {
		return NULL;
	}
	RBin *bin = binfile? binfile->rbin: NULL;
	if (!strncmp (str, "sym.", 4)) {
		str += 4;
	}
	if (!strncmp (str, "imp.", 4)) {
		str += 4;
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
		type = r_bin_lang_type (binfile, def, str);
	}
	switch (type) {
	case R_BIN_NM_JAVA: return r_bin_demangle_java (str);
	case R_BIN_NM_RUST: return r_bin_demangle_rust (binfile, str, vaddr);
	case R_BIN_NM_OBJC: return r_bin_demangle_objc (NULL, str);
	case R_BIN_NM_SWIFT: return r_bin_demangle_swift (str, bin? bin->demanglercmd: false);
	case R_BIN_NM_CXX: return r_bin_demangle_cxx (binfile, str, vaddr);
	case R_BIN_NM_DLANG: return r_bin_demangle_plugin (bin, "dlang", str);
	}
	return NULL;
}

#ifdef TEST
main() {
	char *out, str[128];
	strncpy (str, "_Z1hic", sizeof (str)-1);
	strncpy (str, "main(Ljava/lang/String;I)V", sizeof (str)-1);
	strncpy (str, "main([Ljava/lang/String;)V", sizeof (str)-1);
	strncpy (str, "foo([III)Ljava/lang/Integer;", sizeof (str)-1);
	//out = cplus_demangle_v3 (str, flags);
	out = r_bin_demangle_java (str); //, flags);
	printf ("INPUT (%s)\n", str);
	printf ("OUTPUT (%s)\n", out);
}
#endif
