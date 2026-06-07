// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// Scheme dispatcher for the C++ demangling engines.

#include <r_util.h>
#include "cxx2.h"

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
