// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// Scheme dispatcher and the Rust-legacy post-processing layer. The heavy
// lifting lives in itanium.c / rust.c / dlang.c.

#include <r_util.h>
#include "cxx2.h"

// Rust legacy symbols are Itanium-mangled with a trailing 17h<hash> segment and
// a set of $..$ escapes. We reuse the Itanium engine then unescape the result.
static char *rust_legacy_cleanup(char *str) {
	if (!str) {
		return NULL;
	}
	struct { const char *seq; char ch; } map[] = {
		{ "$SP$", '@' }, { "$BP$", '*' }, { "$RF$", '&' }, { "$LT$", '<' },
		{ "$GT$", '>' }, { "$LP$", '(' }, { "$RP$", ')' }, { "$C$", ',' },
		{ "$u20$", ' ' }, { "$u22$", '"' }, { "$u27$", '\'' }, { "$u2b$", '+' },
		{ "$u3b$", ';' }, { "$u5b$", '[' }, { "$u5d$", ']' }, { "$u7e$", '~' },
		{ NULL, 0 }
	};
	char *in = str, *out = str;
	while (*in) {
		if (*in == '$') {
				int i, matched = 0;
				for (i = 0; map[i].seq; i++) {
					size_t l = strlen (map[i].seq);
					if (r_str_startswith (in, map[i].seq)) {
						*out++ = map[i].ch;
						in += l;
						matched = 1;
					break;
				}
			}
			if (matched) {
				continue;
			}
		}
		if (in[0] == '.' && in[1] == '.') {
			*out++ = ':';
			*out++ = ':';
			in += 2;
			continue;
		}
		*out++ = *in++;
	}
	*out = 0;
	return str;
}

char *r_demangle_rust(const char *mangled) {
	if (!mangled) {
		return NULL;
	}
	// v0 mangling: _R...  (handled in rust.c)
	const char *p = mangled;
	if (p[0] == '_' && p[1] == 'R') {
		return r_demangle_rust_v0 (mangled);
	}
	// legacy: Itanium engine + unescape
	char *itn = r_demangle_itanium (mangled);
	return rust_legacy_cleanup (itn);
}

char *r_demangle_cxx2(const char *mangled) {
	if (R_STR_ISEMPTY (mangled)) {
		return NULL;
	}
	const char *p = mangled;
	if (p[0] == '_' && p[1] == '_' && p[2] == 'Z') {
		p++;
	}
	if (p[0] == '_') {
		if (p[1] == 'Z') {
			return r_demangle_itanium (mangled);
		}
		if (p[1] == 'R') {
			return r_demangle_rust (mangled);
		}
		if (p[1] == 'D') {
			return r_demangle_dlang (mangled);
		}
	}
	// cfront-family (pre-Itanium) schemes overlap heavily; try the strict
	// matchers first (ARM is full-consumption strict, so it only claims
	// genuinely ARM-mangled names) then fall back to the looser g++ v2 engine.
	char *out = r_demangle_ibmxl (mangled);
	if (!out) {
		out = r_demangle_arm (mangled);
	}
	if (!out) {
		out = r_demangle_gnu_v2 (mangled);
	}
	return out;
}
