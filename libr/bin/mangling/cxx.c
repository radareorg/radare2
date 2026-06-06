/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_bin.h>
#include "../i/private.h"
#include "./cxx/demangle.h"
#include "./cxx2/cxx2.h"

R_API char *r_bin_demangle_cxx(RBinFile *bf, const char *str, ut64 vaddr) {
	const char *rawname = str;
	// DMGL_TYPES | DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE
	// | DMGL_RET_POSTFIX | DMGL_TYPES;
	int i;
#if WITH_GPL
	int flags = DMGL_NO_OPTS | DMGL_PARAMS;
#endif
	const char *prefixes[] = {
		"__symbol_stub1_",
		"reloc.",
		"sym.imp.",
		"imp.",
		NULL
	};
	char *tmpstr = strdup (str);
	char *p = tmpstr;
	const char p0 = *p;
	if (p0 == 0) {
		return p;
	}
	bool stripped_us = false;
	if (p0 == p[1] && p0 == '_') {
		p++;
		stripped_us = true;
	}
	for (i = 0; prefixes[i]; i++) {
		int plen = strlen (prefixes[i]);
		if (!strncmp (p, prefixes[i], plen)) {
			p += plen;
			break;
		}
	}
	// remove CXXABI suffix
	char *cxxabi = strstr (p, "@@CXXABI");
	char *glibcxx = strstr (p, "@GLIBCXX");
	if (cxxabi) {
		*cxxabi = '\0';
	} else if (glibcxx) {
		if (glibcxx > p && glibcxx[-1] == '@') {
			glibcxx[-1] = '\0';
		} else {
			*glibcxx = '\0';
		}
	}
	/* JNI entry points (Java_*) are extern "C", never C++ mangled; the cfront
	 * demanglers below would otherwise misread their embedded "__" as a
	 * signature separator. */
	if (r_str_startswith (p, "Java_")) {
		free (tmpstr);
		return NULL;
	}
	/* Prefer the in-house MIT demangler (cxx2); fall back to the GPL libiberty
	 * demangler for the rare constructs cxx2 does not yet handle, so there are
	 * no regressions during the migration. */
	char *out = r_demangle_ibmxl (p);
	if (!out) {
		out = r_demangle_itanium (p);
	}
#if WITH_GPL
	if (!out) {
		out = cplus_demangle_v3 (p, flags);
	}
#endif
	if (!out) {
		// pre-Itanium g++ 2.x ABI (foo__1Ai, __ls__3fooi, _$_3foo, ...).
		// v2 ctor/operator markers are a leading "__", which the macOS-style
		// underscore strip above would clobber, so undo it for this engine.
		char *gv2in = (stripped_us && p > tmpstr && p[-1] == '_') ? p - 1 : p;
		out = r_demangle_gnu_v2 (gv2in);
	}
	free (tmpstr);
	if (out) {
		char *sign = (char *)strchr (out, '(');
		if (sign) {
			char *str = out;
			char *ptr = NULL;
			char *nerd = NULL;
			for (;;) {
				ptr = strstr (str, "::");
				if (!ptr || ptr > sign) {
					break;
				}
				nerd = ptr;
				str = ptr + 1;
			}
			if (R_STR_ISNOTEMPTY (nerd)) {
				*nerd = 0;
				if (bf) {
					RBinSymbol *sym = r_bin_file_add_method (bf, rawname, out, nerd + 2, 0);
					if (sym) {
						if (sym->vaddr != 0 && sym->vaddr != vaddr) {
							if (bf && bf->rbin && bf->rbin->options.verbose) {
								R_LOG_WARN ("Dupped method found: %s", r_bin_name_tostring (sym->name));
							}
						}
						if (sym->vaddr == 0) {
							sym->vaddr = vaddr;
						}
					}
				}
				*nerd = ':';
			}
		}
	}
	return out;
}
