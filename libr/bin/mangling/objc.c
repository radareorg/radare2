/* radare - LGPL - Copyright 2012-2025 - pancake */

#include <r_bin.h>
#include "../i/private.h"

R_API char *r_bin_demangle_objc(RBinFile *bf, const char *sym) {
	R_RETURN_VAL_IF_FAIL ((!bf || (bf && bf->bo && bf->bo->classes)) && sym, NULL);
	const char *rawname = sym;
	char *clas = NULL;
	char *name = NULL;
	char *args = NULL;
	int i, nargs = 0;
	const char *type = NULL;

	if (bf && bf->bo && bf->bo->classes) {
		bf = NULL;
	}
	/* classes */
	if (r_str_startswith (sym, "_OBJC_")) {
		const char *sym2 = sym + strlen ("_OBJC_");
		if (r_str_startswith (sym2, "Class_")) {
			const char *className = sym + 12;
			if (bf) {
				r_bin_file_add_class (bf, className, NULL, R_BIN_ATTR_PUBLIC);
			}
			return r_str_newf ("class %s", className);
		}
		if (r_str_startswith (sym2, "CLASS_$_")) {
			const char *className = sym + 14;
			if (bf) {
				r_bin_file_add_class (bf, className, NULL, R_BIN_ATTR_PUBLIC);
			}
			return r_str_newf ("class %s", className);
		}
		/* fields */
		if (r_str_startswith (sym2, "IVAR_$_")) {
			type = "field";
			clas = strdup (sym + 13);
			char *p = strchr (clas, '.');
			if (p) {
				*p = 0;
				name = strdup (p + 1);
			} else {
				name = NULL;
			}
			if (bf) {
				r_bin_file_add_field (bf, clas, name);
			}
		}
	}
	/* methods */
	if (sym && sym[0] && sym[1] == '[') { // apple style
		if (sym[0] == '+') {
			type = "static";
		} else if (sym[0] == '-') {
			type = "public";
		}
		if (type) {
			free (clas);
			clas = strdup (sym + 2);
			name = strchr (clas, ' ');
			if (name) {
				*name++ = 0;
				name = strdup (name);
				if (!name) {
					free (clas);
					return NULL;
				}
				for (i = 0; name[i]; i++) {
					if (name[i] == ']') {
						name[i] = 0;
					} else if (name[i] == ':') {
						nargs++;
						name[i] = 0;
					}
				}
			}
		}
	}
	if (sym[0] == '_' && sym[1] && sym[2] == '_') { // gnu style
		free (clas);
		clas = strdup (sym + 3);
		args = strstr (clas, "__");
		if (!args) {
			free (clas);
			if (name != clas) {
				free (name);
			}
			return NULL;
		}
		*args = 0;
		free (name);
		name = strdup (args + 2);
		if (!name) {
			free (clas);
			return NULL;
		}
		args = NULL;
		for (i = 0; name[i]; i++) {
			if (name[i] == '_') {
				name[i] = 0;
				nargs++;
			}
		}
		if (sym[1] == 'i') {
			type = "public";
		} else if (sym[1] == 'c') {
			type = "static";
		}
	}
	char *ret = NULL;
	if (type) {
		if (!strcmp (type, "field")) {
			ret = r_str_newf ("field int %s::%s", clas, name);
		} else {
			if (nargs) {
				RStrBuf *sb = r_strbuf_new ("");
				for (i = 0; i < nargs; i++) {
					r_strbuf_append (sb, "int");
					if (i + 1 < nargs) {
						r_strbuf_append (sb, ", ");
					}
				}
				args = r_strbuf_drain (sb);
			} else {
				args = strdup ("");
			}
			if (R_STR_ISNOTEMPTY (name) && type) {
				ret = r_str_newf ("%s int %s::%s(%s)", type, clas, name, args);
				if (bf) {
					r_bin_file_add_method (bf, rawname, clas, name, nargs);
				}
			}
		}
	}
	free (clas);
	free (args);
	free (name);
	return ret;
}
