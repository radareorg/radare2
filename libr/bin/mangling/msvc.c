/* radare - LGPL - Copyright 2015-2025 - inisider, pancake, murphy */

#include <r_bin.h>
#include "./microsoft.h"

static bool is_probable_itanium_rtti_name(const char *name) {
	const unsigned char *s = (const unsigned char *)name;
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	if (*s == '.' || *s == '?' || *s == '@' || *s == '$') {
		return false;
	}
	if (*s == '_' && s[1] == 'Z') {
		return true;
	}
	const char *terminator = strchr ((const char *)s, 'E');
	if (!terminator) {
		return false;
	}
	while (s < (const unsigned char *)terminator) {
		if (isdigit ((unsigned char)*s)) {
			return true;
		}
		s++;
	}
	return false;
}

static void normalize_template_spacing(char *text) {
	char *src = text;
	char *dst = text;
	int depth = 0;
	if (!text) {
		return;
	}
	while (*src) {
		char ch = *src;
		if (ch == '<') {
			depth++;
			*dst++ = ch;
			src++;
			while (*src == ' ') {
				src++;
			}
			continue;
		}
		if (depth > 0) {
			if (ch == ',') {
				*dst++ = ch;
				src++;
				while (*src == ' ') {
					src++;
				}
				continue;
			}
			if (ch == '>') {
				char *tmp = dst;
				while (tmp > text && tmp[-1] == ' ') {
					tmp--;
				}
				dst = tmp;
				if (depth > 0) {
					depth--;
				}
				*dst++ = ch;
				src++;
				continue;
			}
		}
		*dst++ = ch;
		src++;
	}
	*dst = '\0';
}

static char *demangle_itanium_rtti_name(const char *name) {
	char *prefixed = NULL;
	const char *candidate = name;
	if (!is_probable_itanium_rtti_name (name)) {
		return NULL;
	}
	if (!(name[0] == '_' && name[1] == 'Z')) {
		prefixed = r_str_newf ("_Z%s", name);
		if (!prefixed) {
			return NULL;
		}
		candidate = prefixed;
	}
	char *result = r_bin_demangle (NULL, "cxx", candidate, 0, false);
	if (result) {
		normalize_template_spacing (result);
	}
	free (prefixed);
	return result;
}

R_API char *r_bin_demangle_msvc(const char *str) {
	char *out = NULL;
	SDemangler *mangler = 0;

	if (create_demangler (&mangler) == eDemanglerErrOK && mangler) {
		if (init_demangler (mangler, (char *)str) == eDemanglerErrOK) {
			mangler->demangle (mangler, &out/*demangled_name*/);
		}
		free_demangler (mangler);
		mangler = NULL;
	}
	if (!out) {
		out = demangle_itanium_rtti_name (str);
	}
	return out;
}
