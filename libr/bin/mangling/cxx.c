/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_bin.h>
#include "../i/private.h"
#if WITH_GPL
#include "./cxx/demangle.h"
#endif
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
	// The pre-Itanium cfront-family ABIs (IBM XL, ARM, g++ 2.x) encode their
	// ctor/operator markers as a leading "__" (__ct__, __ls__, _$_, ...) which
	// the macOS-style underscore strip above would clobber, so feed them the
	// un-stripped symbol.
	char *gv2in = (stripped_us && p > tmpstr && p[-1] == '_') ? p - 1 : p;
	char *out = NULL;
	// ARM/cfront templates (__pt__) are ARM-specific: IBM XL uses a different
	// template syntax, so only the ARM engine can decode them (T5<x> vs the raw
	// T5__pt__3_1x). It is full-consumption strict, so it never claims a
	// non-ARM name. Let it go first for those.
	if (strstr (p, "__pt__")) {
		out = r_demangle_arm (gv2in);
	}
	if (!out) {
		out = r_demangle_ibmxl (gv2in);
	}
	if (!out) {
		out = r_demangle_itanium (p);
	}
#if WITH_GPL
	if (!out) {
		out = cplus_demangle_v3 (p, flags);
	}
#endif
	if (!out) {
		// ARM/cfront (__ct__1cFi, bar__3fooFPv, ...) is full-consumption strict,
		// so it only claims genuinely ARM-mangled names; try it before the
		// looser g++ 2.x engine (foo__1Ai, __ls__3fooi, _$_3foo, ...).
		out = r_demangle_arm (gv2in);
		if (!out) {
			out = r_demangle_gnu_v2 (gv2in);
		}
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
