/* radare - LGPL - Copyright 2011-2026 - pancake */

#include <r_bin.h>

R_API char *r_bin_demangle_java(const char *str) {
	if (R_STR_ISEMPTY (str)) {
		return NULL;
	}
	const char *descriptor = strchr (str, '(');
	if (!descriptor) {
		return NULL;
	}
	char *name = descriptor == str? NULL: r_str_ndup (str, descriptor - str);
	RBinJavaMember *member = r_bin_java_member_parse (NULL, name, descriptor,
		R_BIN_JAVA_MEMBER_METHOD, 0);
	free (name);
	if (!member) {
		return NULL;
	}
	char *result = member->definition;
	member->definition = NULL;
	r_bin_java_member_free (member);
	return result;
}
