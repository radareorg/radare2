/* radare - LGPL - Copyright 2011-2018 - pancake */

#include <r_bin.h>

#define RS(from, to) (replace_seq ((const char **)&in, &out, (const char *)(from), to))

static bool replace_seq (const char **in, char **out, const char *seq, char value) {
	size_t len = strlen (seq);

	if (strncmp (*in, seq, len)) {
		return false;
	}

	**out = value;

	*in += len;
	*out += 1;

	return true;
}

R_API char *r_bin_demangle_rust (RBinFile *binfile, const char *sym, ut64 vaddr) {
	int len;
	char *str, *out, *in;

	str = r_bin_demangle_cxx (binfile, sym, vaddr);
	
	if (!str) {
		return str;
	}

	out = in = str;
	len = strlen (str);

	if (*in == '_') {
		in++;
		len--;
	}

	while ((len = strlen (in)) > 0) {
		if (!(*in == '$' && (RS("$SP$", '@')
				|| RS("$BP$", '*')
				|| RS("$RF$", '&')
				|| RS("$LT$", '<')
				|| RS("$GT$", '>')
				|| RS("$LP$", '(')
				|| RS("$RP$", ')')
				|| RS("$C$", ',')
				// maybe a good idea to replace all utf-sequences by regexp \$u[0-9a-f]{2}\$ or so
				|| RS("$u20$", ' ')
				|| RS("$u22$", '\"')
				|| RS("$u27$", '\'')
				|| RS("$u2b$", '+')
				|| RS("$u3b$", ';')
				|| RS("$u5b$", '[')
				|| RS("$u5d$", ']')
				|| RS("$u7e$", '~')))) {
			if (*in == '.') {
				if (len > 0 && in[1] == '.') {
					in += 2;
					*out++ = ':';
					*out++ = ':';
					len--;
				} else {
					in += 1;
					*out = '-';
				}
			} else {
				*out++ = *in++;
			}
		}
	}
	*out = '\0';

	return str;
}
