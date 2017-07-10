/* radare - LGPL - Copyright 2011-2016 - pancake */

#include <r_bin.h>
#include <cxx/demangle.h>

//TODO: mangler_branch: remove?
#include "mangling/demangler.h"

R_API void r_bin_demangle_list(RBin *bin) {
	const char *langs[] = { "cxx", "java", "objc", "swift", "dlang", "msvc", NULL };
	RBinPlugin *plugin;
	RListIter *it;
	int i;
	if (!bin) return;
	for (i=0; langs[i]; i++) {
		eprintf ("%s\n", langs[i]);
	}
	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->demangle) {
			eprintf ("%s\n", plugin->name);
		}
	}
}

R_API char *r_bin_demangle_plugin(RBin *bin, const char *name, const char *str) {
	RBinPlugin *plugin;
	RListIter *it;
	if (!bin || !name || !str) return NULL;
	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->demangle) {
			return plugin->demangle (str);
		}
	}
	return NULL;
}

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

R_API char *r_bin_demangle_msvc(const char *str) {
	char *out = NULL;
	SDemangler *mangler = 0;

	create_demangler (&mangler);
	if (!mangler) return NULL;
	if (init_demangler (mangler, (char *)str) == eDemanglerErrOK) {
		mangler->demangle (mangler, &out/*demangled_name*/);
	}
	free_demangler (mangler);
	return out;
}

R_API char *r_bin_demangle_cxx(RBinFile *binfile, const char *str, ut64 vaddr) {
	char *out;
	// DMGL_TYPES | DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE
	// | DMGL_RET_POSTFIX | DMGL_TYPES;
	int i;
#if WITH_GPL
	int flags = DMGL_NO_OPTS | DMGL_PARAMS;
#endif
	const char *prefixes[] = {
		"__symbol_stub1_",
		"reloc.",
		"sym.imp.",
		"imp.",
		NULL
	};
	if (str[0] == str[1] && *str == '_') {
		str++;
	} {
		for (i = 0; prefixes[i]; i++) {
			int plen = strlen (prefixes[i]);
			if (!strncmp (str, prefixes[i], plen)) {
				str += plen;
				break;
			}
		}
	}
#if WITH_GPL
	out = cplus_demangle_v3 (str, flags);
#else
	/* TODO: implement a non-gpl alternative to c++v3 demangler */
	out = NULL;
#endif
	if (out) {
		r_str_replace_char (out, ' ', 0);
	}
	{
		/* extract class/method information */
		char *nerd = (char*)r_str_last (out, "::");
		if (nerd && *nerd) {
			*nerd = 0;
			RBinSymbol *sym = r_bin_class_add_method (binfile, out, nerd + 2, 0);
			if (sym) {
				sym->vaddr = vaddr;
			}
			*nerd = ':';
		}
	}
	return out;
}

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
		if (binfile) r_bin_class_add_field (binfile, clas, name);
	}
	/* methods */
	if (sym && sym[0] && sym[1] == '[') { // apple style
		if (sym[0] == '+') type = "static";
		else if (sym[0] == '-') type = "public";
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
				for(i = 0;i < nargs; i++) {
					strcat (args, arg);
					if (i + 1 < nargs)
						strcat (args, ", ");
				}
			} else {
				args = strdup ("");
			}
			if (type && name && *name) {
				ret = r_str_newf ("%s int  %s::%s(%s)", type, clas, name, args);
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

#define RS(from, to) (replace_seq ((const char **)&in, &out, (const char *)from, to))

R_API char *r_bin_demangle_rust(RBinFile *binfile, const char *sym, ut64 vaddr) {
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

R_API int r_bin_demangle_type (const char *str) {
	if (!str || !*str) {
		return R_BIN_NM_NONE;
	} if (!strcmp (str, "swift")) {
		return R_BIN_NM_SWIFT;
	} if (!strcmp (str, "java")){
		return R_BIN_NM_JAVA;
	} if (!strcmp (str, "objc")){
		return R_BIN_NM_OBJC;
	} if (!strcmp (str, "cxx")){
		return R_BIN_NM_CXX;
	} if (!strcmp (str, "dlang")){
		return R_BIN_NM_DLANG;
	} if (!strcmp (str, "msvc")){
		return R_BIN_NM_MSVC;
	} if (!strcmp (str, "rust")){
		return R_BIN_NM_RUST;
	}
	return R_BIN_NM_NONE;
}

R_API bool r_bin_lang_rust(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RBinSymbol *sym;
	RListIter *iter;
	int haslang = false;

	if (info) {
		r_list_foreach (o->symbols, iter, sym) {
			if (sym->name && strstr (sym->name, "_$LT$")) {
				haslang = true;
				info->lang = "rust";
				break;
			}
		}
	}
	// NOTE: if the rust binary is stripped we can check
	// if the strings contain 'rust', but this can be too
	// time consuming and spawn some false positives and,
	// as long as lang detection is only useful for demangling
	// there's no utility on catching this case.
	return haslang;
}

R_API int r_bin_lang_type(RBinFile *binfile, const char *def, const char *sym) {
	int type = 0;
	RBinPlugin *plugin;
	if (sym && sym[0] == sym[1] && sym[0] == '_') {
		type = R_BIN_NM_CXX;
	}
	if (def && *def) {
		type = r_bin_demangle_type (def);
		if (type != R_BIN_NM_NONE)
			return type;
	}
	plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->demangle_type) {
		type = plugin->demangle_type (def);
	} else {
		if (binfile->o && binfile->o->info) {
			type = r_bin_demangle_type (binfile->o->info->lang);
		}
	}
	if (type == R_BIN_NM_NONE) {
		type = r_bin_demangle_type (def);
	}
	return type;
}

R_API char *r_bin_demangle(RBinFile *binfile, const char *def, const char *str, ut64 vaddr) {
	int type = -1;
	RBin *bin;
	if (!binfile || !str || !*str) {
		return NULL;
	}
	bin = binfile->rbin;
	if (!strncmp (str, "sym.", 4)) {
		str += 4;
	}
	if (!strncmp (str, "imp.", 4)) {
		str += 4;
	}
	if (!strncmp (str, "__", 2)) {
		if (str[2] == 'T') {
			type = R_BIN_NM_SWIFT;
		} else {
			type = R_BIN_NM_CXX;
		//	str++;
		}
	}
	// if str is sym. or imp. when str+=4 str points to the end so just return
	if (!*str) {
		return NULL;
	}
	if (type == -1) {
		type = r_bin_lang_type (binfile, def, str);
	}
	switch (type) {
	case R_BIN_NM_JAVA: return r_bin_demangle_java (str);
	case R_BIN_NM_RUST: return r_bin_demangle_rust (binfile, str, vaddr);
	case R_BIN_NM_OBJC: return r_bin_demangle_objc (NULL, str);
	case R_BIN_NM_SWIFT: return r_bin_demangle_swift (str, bin->demanglercmd);
	case R_BIN_NM_CXX: return r_bin_demangle_cxx (binfile, str, vaddr);
	case R_BIN_NM_DLANG: return r_bin_demangle_plugin (bin, "dlang", str);
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
