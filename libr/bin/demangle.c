/* radare - LGPL - Copyright 2011-2014 - pancake */

#include <r_bin.h>
#include <cxx/demangle.h>

// http://code.google.com/p/smali/wiki/TypesMethodsAndFields
R_API char *r_bin_demangle_java(const char *str) {
	const char *w = NULL;
	int is_array = 0;
	const char *ptr;
	int is_ret = 0;
	int wlen = 0;
	RBuffer *buf;
	int n = 0;
	char *ret;

	ptr = strchr (str, '(');
	if (!ptr)
		return NULL;
	buf = r_buf_new ();
	if (!buf) return NULL;
	r_buf_append_bytes (buf, (const ut8*)str, (int)(size_t)(ptr-str));
	r_buf_append_bytes (buf, (const ut8*)" (", 2);
	while (*str) {
		switch (*str) {
		case ')':
			is_ret = 1;
			break;
		case '[':
			is_array = 1;
			break;
		case 'L':
			str++;
			ptr = strchr (str, ';');
			if (ptr) {
				w = str;
				wlen = (int)(size_t)(ptr-str);
			}
			str = ptr;
			break;
		case 'I': w = "int"; wlen = 3; break;
		case 'C': w = "char"; wlen = 4; break;
		case 'B': w = "byte"; wlen = 4; break;
		case 'V': w = "void"; wlen = 4; break;
		case 'J': w = "long"; wlen = 4; break;
		case 'F': w = "float"; wlen = 5; break;
		case 'S': w = "short"; wlen = 5; break;
		case 'D': w = "double"; wlen = 6; break;
		case 'Z': w = "boolean"; wlen = 7; break;
		}
		if (w) {
			if (is_ret) {
				r_buf_prepend_bytes (buf, (const ut8*)" ", 1);
				r_buf_prepend_bytes (buf, (const ut8*)w, wlen);
				r_buf_append_bytes (buf, (const ut8*)")", 1);
				break;
			} else {
				if (n++>0)
					r_buf_append_bytes (buf, (const ut8*)", ", 2);
				r_buf_append_bytes (buf, (const ut8*)w, wlen);
			}
			if (is_array) {
				r_buf_append_bytes (buf, (const ut8*)"[]", 2);
				is_array = 0;
			}
		}
		w = NULL;
		if (!str) break;
		str++;
	}
	ret = r_buf_to_string (buf);
	r_buf_free (buf);
	return ret;
}

R_API char *r_bin_demangle_cxx(const char *str) {
	char *out;
	// DMGL_TYPES | DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE
	// | DMGL_RET_POSTFIX | DMGL_TYPES;
	int i, flags = DMGL_NO_OPTS;
	const char *prefixes[] = {
		"__symbol_stub1_",
		"reloc.",
		"sym.imp.",
		"imp.",
		NULL
	};
	if (str[0]==str[1] && *str=='_') {
		str++;
	} {
		for (i=0; prefixes[i]; i++) {
			int plen = strlen (prefixes[i]);
			if (!strncmp (str, prefixes[i], plen)) {
				str += plen;
				break;
			}
		}
	}
	out = cplus_demangle_v3 (str, flags);

	if (out)
		r_str_replace_char (out, ' ', 0);

	return out;
}

R_API char *r_bin_demangle_objc(RBinFile *binfile, const char *sym) {
	char *ret = NULL;
	char *clas = NULL;
	char *name = NULL;
	char *args = NULL;
	int i, nargs = 0;
	const char *type = NULL;
	/* classes */
	if (!strncmp (sym, "_OBJC_Class_", 12)) {
		ret = malloc (10+strlen (sym));
		sprintf (ret, "class %s", sym+12);
		if (binfile) r_bin_class_new (binfile, sym+12, NULL, R_BIN_CLASS_PUBLIC);
		return ret;
	} else
	if (!strncmp (sym, "_OBJC_CLASS_$_", 14)) {
		ret = malloc (10+strlen (sym));
		sprintf (ret, "class %s", sym+14);
		if (binfile) r_bin_class_new (binfile, sym+14, NULL, R_BIN_CLASS_PUBLIC);
		return ret;
	} else
	/* fields */
	if (!strncmp (sym, "_OBJC_IVAR_$_", 13)) {
		char *p;
		clas = strdup (sym+13);
		p = strchr (clas, '.');
		type = "field";
		if (p) {
			*p = 0;
			name = strdup (p+1);
		} else name = NULL;
		if (binfile) r_bin_class_add_field (binfile, clas, name);
	} else
	/* methods */
	if (sym[1] == '[') { // apple style
		if (sym[0] == '+') type = "static";
		else if (sym[0] == '-') type = "public";
		if (type) {
			clas = strdup (sym+2);
			name = strchr (clas, ' ');
			if (name) {
				*name++ = 0;
				name = strdup (name);
				for (i=0; name[i]; i++) {
					if (name[i]==']') {
						name[i] = 0;
					} else
					if (name[i]==':') {
						nargs++;
						name[i] = 0;
					}
				}
			}
		}
	} else
	if (sym[0]=='_' && sym[2]=='_') { // gnu style
		clas = strdup (sym+3);
		args = strstr (clas, "__");
		if (!args) {
			free (clas);
			return NULL;
		}
		*args = 0;
		name = strdup (args+2);
		args = NULL;
		for (i=0; name[i]; i++) {
			if (name[i]=='_') {
				name[i] = 0;
				nargs++;
			}
		}
		if (sym[1] == 'i') type = "public";
		else if (sym[1] == 'c') type = "static";
	}
	if (type) {
		if (!strcmp (type, "field")) {
			int namelen = name?strlen (name):0;
			ret = malloc (strlen (clas)+namelen+32);
			if (ret) sprintf (ret, "field int %s::%s", clas, name);
		} else {
			if (nargs) {
				const char *arg = "int";
				args = malloc (((strlen (arg)+4) * nargs)+1);
				args[0] = 0;
				for(i=0;i<nargs; i++) {
					strcat (args, arg);
					if (i+1<nargs)
						strcat (args, ", ");
				}
			} else args = strdup ("");
				if (type && name && *name) {
				ret = malloc (strlen (type)+strlen (name)+
					strlen(clas)+strlen(args)+15);
				sprintf (ret, "%s int %s::%s(%s)", type, clas, name, args);
				if (binfile) r_bin_class_add_method (binfile, clas, name, nargs);
			}
		}
	}
	free (clas);
	free (args);
	free (name);
	return ret;
}

R_API int r_bin_demangle_type (const char *str) {
	// XXX: add
	return R_BIN_NM_CXX;
}

R_API char *r_bin_demangle (RBinFile *binfile, const char *str) {
	int type;
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->demangle_type)
		type = plugin->demangle_type (str);
	else type = r_bin_demangle_type (str);
	switch (type) {
	case R_BIN_NM_JAVA: return r_bin_demangle_java (str);
	case R_BIN_NM_CXX: return r_bin_demangle_cxx (str);
	}
	return NULL;
}

#ifdef TEST
main() {
	char *out, str[128];
	strncpy (str, "_Z1hic", sizeof (str)-1);
	strncpy (str, "main(Ljava/lang/String;I)V", sizeof (str)-1);
	strncpy (str, "main([Ljava/lang/String;)V", sizeof (str)-1);
	strncpy (str, "foo([III)Ljava/lang/Integer;", sizeof (str)-1);
	//out = cplus_demangle_v3 (str, flags);
	out = r_bin_demangle_java (str); //, flags);
	printf ("INPUT (%s)\n", str);
	printf ("OUTPUT (%s)\n", out);
}
#endif
