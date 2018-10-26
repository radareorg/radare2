/* radare - LGPL - Copyright 2012-2015 - pancake */

#include <r_bin.h>

R_API char *r_bin_demangle_objc(RBinFile *binfile, const char *sym) {
	char *ret = NULL;
	char *clas = NULL;
	char *name = NULL;
	char *args = NULL;
	int i, nargs = 0;
	const char *type = NULL;

	if (!binfile || !sym) {
		return NULL;
	}
	if (binfile && binfile->o && binfile->o->classes) {
		binfile = NULL;
	}
	/* classes */
	if (!strncmp (sym, "_OBJC_Class_", 12)) {
		ret = r_str_newf ("class %s", sym + 12);
		if (binfile) {
			r_bin_class_new (binfile, sym + 12,
				NULL, R_BIN_CLASS_PUBLIC);
		}
		return ret;
	}
	if (!strncmp (sym, "_OBJC_CLASS_$_", 14)) {
		ret = r_str_newf ("class %s", sym + 14);
		if (binfile) {
			r_bin_class_new (binfile, sym + 14,
				NULL, R_BIN_CLASS_PUBLIC);
		}
		return ret;
	}
	/* fields */
	if (!strncmp (sym, "_OBJC_IVAR_$_", 13)) {
		char *p;
		clas = strdup (sym + 13);
		p = strchr (clas, '.');
		type = "field";
		if (p) {
			*p = 0;
			name = strdup (p + 1);
		} else {
			name = NULL;
		}
		if (binfile) {
			r_bin_class_add_field (binfile, clas, name);
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
			clas = strdup (sym + 2);
			name = strchr (clas, ' ');
			if (name) {
				*name++ = 0;
				name = strdup (name);
				if (!name){
					free (clas);
					return NULL;
				}
				for (i = 0; name[i]; i++) {
					if (name[i]==']') {
						name[i] = 0;
					}
					if (name[i]==':') {
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
	if (type) {
		if (!strcmp (type, "field")) {
			ret = r_str_newf ("field int %s::%s", clas, name);
		} else {
			if (nargs) {
				const char *arg = "int";
				args = malloc (((strlen (arg) + 4) * nargs) + 1);
				args[0] = 0;
				for (i = 0;i < nargs; i++) {
					strcat (args, arg);
					if (i + 1 < nargs) {
						strcat (args, ", ");
					}
				}
			} else {
				args = strdup ("");
			}
			if (type && name && *name) {
				ret = r_str_newf ("%s int %s::%s(%s)", type, clas, name, args);
				if (binfile) {
					r_bin_class_add_method (binfile, clas, name, nargs);

				}
			}
		}
	}
	free (clas);
	free (args);
	free (name);
	return ret;
}
