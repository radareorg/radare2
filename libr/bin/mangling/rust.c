/* radare - LGPL - Copyright 2011-2026 - pancake */

#include <r_bin.h>
#include "cxx2/cxx2.h"

// R2R db/formats/mangling/rust

#define RS(from, to) (replace_seq ((const char **)&in, &out, &len, (const char *)(from), to))

static bool replace_seq(const char **in, char **out, size_t *remaining, const char *seq, char value) {
	size_t slen = strlen (seq);

	if (strncmp (*in, seq, slen)) {
		return false;
	}

	**out = value;

	*in += slen;
	*out += 1;
	*remaining -= slen;

	return true;
}

R_API char *r_bin_demangle_rust(RBinFile *binfile, const char *sym, ut64 vaddr) {
	// Rust v0 (RFC 2603) symbols start with "_R" and use their own grammar.
	const char *p = sym;
	if (p && p[0] == '_' && p[1] == '_' && p[2] == 'R') {
		p++;
	}
	if (p && p[0] == '_' && p[1] == 'R') {
		char *v0 = r_demangle_rust_v0 (sym);
		if (v0) {
			return v0;
		}
	}
	// legacy mangling: Itanium-mangled name plus $..$ escapes
	char *str = r_bin_demangle_cxx (binfile, sym, vaddr);

	if (!str) {
		return str;
	}

	char *in = str;
	char *out = str;
	size_t len = strlen (str);
	while (len > 0) {
		if (!(*in == '$' && (RS ("$SP$", '@')
				|| RS ("$BP$", '*')
				|| RS ("$RF$", '&')
				|| RS ("$LT$", '<')
				|| RS ("$GT$", '>')
				|| RS ("$LP$", '(')
				|| RS ("$RP$", ')')
				|| RS ("$C$", ',')
				// maybe a good idea to replace all utf-sequences by regexp \$u[0-9a-f]{2}\$ or so
				|| RS ("$u20$", ' ')
				|| RS ("$u22$", '\"')
				|| RS ("$u27$", '\'')
				|| RS ("$u2b$", '+')
				|| RS ("$u3b$", ';')
				|| RS ("$u5b$", '[')
				|| RS ("$u5d$", ']')
				|| RS ("$u7e$", '~')))) {
			if (*in == '.') {
				if (len > 1 && in[1] == '.') {
					*out++ = ':';
					*out++ = ':';
					in += 2;
					len -= 2;
				} else {
					in++;
					len--;
				}
			} else {
				*out++ = *in++;
				len--;
			}
		}
	}
	*out = '\0';
	return str;
}
