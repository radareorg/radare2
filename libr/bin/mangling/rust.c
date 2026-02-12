/* radare - LGPL - Copyright 2011-2023 - pancake */

#include <r_bin.h>

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
					in += 2;
					*out++ = ':';
					*out++ = ':';
					len -= 2;
				} else {
					in += 1;
					*out++ = '-';
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
