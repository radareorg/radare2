static char *get_rp(const char *rtype) {
	char *rp = NULL;
	switch (rtype[0]) {
	case 'v':
		rp = strdup ("void");
		break;
	case 'c':
		rp = strdup ("char");
		break;
	case 'i':
		rp = strdup ("int");
		break;
	case 's':
		rp = strdup ("short");
		break;
	case 'l':
		rp = strdup ("long");
		break;
	case 'q':
		rp = strdup ("long long");
		break;
	case 'C':
		rp = strdup ("unsigned char");
		break;
	case 'I':
		rp = strdup ("unsigned int");
		break;
	case 'S':
		rp = strdup ("unsigned short");
		break;
	case 'L':
		rp = strdup ("unsigned long");
		break;
	case 'Q':
		rp = strdup ("unsigned long long");
		break;
	case 'f':
		rp = strdup ("float");
		break;
	case 'd':
		rp = strdup ("double");
		break;
	case 'D':
		rp = strdup ("long double");
		break;
	case 'B':
		rp = strdup ("bool");
		break;
	case '#':
		rp = strdup ("CLASS");
		break;
	default:
		rp = strdup ("unknown");
		break;
	}
	return rp;
}

// TODO: move this into r.bin.demangle
// https://nshipster.com/type-encodings/
static char *objc_type_toc(const char *objc_type) {
	if (!objc_type) {
		return strdup ("void*");
	}
	if (*objc_type == '^' && objc_type[1] == '{') {
		char *a = strdup (objc_type + 2);
		char *b = strchr (a, '>');
		if (b) {
			*b = 0;
		}
		a[strlen (a) - 1] = 0;
		return a;
	}
	if (*objc_type == '<') {
		char *a = strdup (objc_type + 1);
		char *b = strchr (a, '>');
		if (b) {
			*b = 0;
		}
		return a;
	}
	if (!strcmp (objc_type, "f")) {
		return strdup ("float");
	}
	if (!strcmp (objc_type, "d")) {
		return strdup ("double");
	}
	if (!strcmp (objc_type, "i")) {
		return strdup ("int");
	}
	if (!strcmp (objc_type, "s")) {
		return strdup ("short");
	}
	if (!strcmp (objc_type, "l")) {
		return strdup ("long");
	}
	if (!strcmp (objc_type, "L")) {
		return strdup ("unsigned long");
	}
	if (!strcmp (objc_type, "*")) {
		return strdup ("char*");
	}
	if (!strcmp (objc_type, "c")) {
		return strdup ("bool");
	}
	if (!strcmp (objc_type, "v")) {
		return strdup ("void");
	}
	if (!strcmp (objc_type, "#")) {
		return strdup ("class");
	}
	if (!strcmp (objc_type, "B")) {
		return strdup ("cxxbool");
	}
	if (!strcmp (objc_type, "Q")) {
		return strdup ("uint64_t");
	}
	if (!strcmp (objc_type, "q")) {
		return strdup ("long long");
	}
	if (!strcmp (objc_type, "C")) {
		return strdup ("uint8_t");
	}
	if (strlen (objc_type) == 1) {
		R_LOG_WARN ("Unknown objc type '%s'", objc_type);
	}
	if (r_str_startswith (objc_type, "@\"")) {
		char *s = r_str_newf ("struct %s", objc_type + 2);
		s[strlen (s) - 1] = '*';
		return s;
	}
	return strdup (objc_type);
}

static char *objc_name_toc(const char *objc_name) {
	const char *n = r_str_lchr (objc_name, ')');
	char *s = strdup (n? n + 1: objc_name);
	char *p = strchr (s, '(');
	if (p) {
		*p = 0;
	}
	return s;
}

static bool objc_is_builtin_property_name(const char *name) {
	return !strcmp (name, "hash")
		|| !strcmp (name, "superclass")
		|| !strcmp (name, "description")
		|| !strcmp (name, "debugDescription");
}

static char *objc_decl_type(const char *field_type, bool *is_object) {
	if (is_object) {
		*is_object = false;
	}
	if (R_STR_ISEMPTY (field_type)) {
		if (is_object) {
			*is_object = true;
		}
		return strdup ("id");
	}
	if (!strcmp (field_type, "struct objc_class *")) {
		return strdup ("Class");
	}
	if (r_str_startswith (field_type, "@\"")) {
		char *klass = strdup (field_type + 2);
		char *end = klass? strchr (klass, '"'): NULL;
		if (end) {
			*end = 0;
		}
		char *out = R_STR_ISNOTEMPTY (klass)? r_str_newf ("%s *", klass): strdup ("id");
		free (klass);
		if (is_object) {
			*is_object = true;
		}
		return out? out: strdup ("id");
	}
	char *ftype = objc_type_toc (field_type);
	if (!ftype || !strcmp (ftype, "unknown")) {
		free (ftype);
		if (is_object) {
			*is_object = true;
		}
		return strdup ("id");
	}
	if (!strcmp (ftype, "bool") || !strcmp (ftype, "cxxbool")) {
		free (ftype);
		return strdup ("BOOL");
	}
	if (!strcmp (ftype, "class") || !strcmp (ftype, "CLASS")) {
		free (ftype);
		return strdup ("Class");
	}
	if (is_object) {
		*is_object = !strcmp (ftype, "id");
	}
	return ftype;
}

static bool objc_has_property(RBinClass *c, const char *pname, int pref) {
	RListIter *iter;
	RBinField *f;
	r_list_foreach (c->fields, iter, f) {
		if (f->kind != R_BIN_FIELD_KIND_PROPERTY || !f->name) {
			continue;
		}
		const char *fname = r_bin_name_tostring2 (f->name, pref);
		if (R_STR_ISNOTEMPTY (fname) && !strcmp (fname, pname)) {
			return true;
		}
	}
	return false;
}

static char *objc_guess_property_type(RBinClass *c, const char *pname, int pref, bool *is_object) {
	RListIter *iter;
	RBinField *f;
	r_list_foreach (c->fields, iter, f) {
		if (f->kind == R_BIN_FIELD_KIND_PROPERTY || !f->name) {
			continue;
		}
		const char *fname = r_bin_name_tostring2 (f->name, pref);
		if (R_STR_ISEMPTY (fname)) {
			continue;
		}
		bool match = !strcmp (fname, pname) || (*fname == '_' && !strcmp (fname + 1, pname));
		if (match) {
			return objc_decl_type (f->type? r_bin_name_tostring2 (f->type, pref): NULL, is_object);
		}
	}
	return objc_decl_type (NULL, is_object);
}

static char *objc_method_return_type(RBinClass *c, const char *method_name, RBinSymbol *sym, int pref) {
	char *rp = (sym->rtype && sym->rtype[0] != '@')? get_rp (sym->rtype): NULL;
	if (!rp) {
		rp = strdup ("id");
	} else if (!strcmp (rp, "bool")) {
		free (rp);
		rp = strdup ("BOOL");
	} else if (!strcmp (rp, "CLASS") || !strcmp (rp, "class")) {
		free (rp);
		rp = strdup ("Class");
	} else if (!strcmp (rp, "unknown")) {
		free (rp);
		rp = strdup ("id");
	}
	if (!strchr (method_name, ':') && !strcmp (rp, "id") && objc_has_property (c, method_name, pref)) {
		char *ptype = objc_guess_property_type (c, method_name, pref, NULL);
		if (R_STR_ISNOTEMPTY (ptype)) {
			free (rp);
			return ptype;
		}
		free (ptype);
	}
	return rp;
}

static char *objc_method_decl(RBinClass *c, const char *method_name, const char *ret_type, bool is_class_method, int pref) {
	const char sign = is_class_method? '+': '-';
	if (*method_name == '.') {
		return r_str_newf ("// %c (%s)%s;", sign, ret_type, method_name);
	}
	if (!strchr (method_name, ':')) {
		return r_str_newf ("%c (%s)%s;", sign, ret_type, method_name);
	}
	RStrBuf *sb = r_strbuf_newf ("%c (%s)", sign, ret_type);
	const char *p = method_name;
	ut32 argc = 0;
	const char *colon;
	while ((colon = strchr (p, ':'))) {
		char *label = r_str_ndup (p, colon - p);
		const char *use_label = R_STR_ISNOTEMPTY (label)? label: "arg";
		char *atype = NULL;
		if (argc == 0) {
			const size_t mlen = strlen (method_name);
			if (colon[1] == '\0' && r_str_startswith (method_name, "set") && mlen > 4) {
				char *prop = r_str_ndup (method_name + 3, mlen - 4);
				if (R_STR_ISNOTEMPTY (prop) && isupper (prop[0])) {
					prop[0] = tolower (prop[0]);
				}
				atype = objc_guess_property_type (c, prop, pref, NULL);
				free (prop);
			}
		}
		r_strbuf_appendf (sb, "%s%s:(%s)arg%u", argc? " ": "", use_label, atype? atype: "id", argc);
		free (label);
		free (atype);
		p = colon + 1;
		argc++;
	}
	r_strbuf_append (sb, ";");
	return r_strbuf_drain (sb);
}

static void classdump_objc(RCore *core, RBinClass *c) {
	const int pref = r_config_get_b (core->config, "asm.demangle")? 'd': 0;
	const char *cname = r_bin_name_tostring2 (c->name, pref);
	if (c->super) {
		int n = 0;
		r_cons_printf (core->cons, "@interface %s", cname);
		RBinName *bn;
		RListIter *iter;
		r_list_foreach (c->super, iter, bn) {
			const char *sk = r_bin_name_tostring2 (bn, pref);
			switch (n) {
			case 0: r_cons_printf (core->cons, " : %s", sk); break;
			case 1: r_cons_printf (core->cons, " <%s", sk); break;
			default: r_cons_printf (core->cons, ", %s", sk); break;
			}
			n++;
		}
		if (n > 1) {
			r_cons_print (core->cons, ">");
		}
		r_cons_newline (core->cons);
	} else {
		r_cons_printf (core->cons, "@interface %s\n", cname);
	}
	RListIter *iter2, *iter3;
	RBinField *f;
	RBinSymbol *sym;
	bool has_ivars = false;
	r_list_foreach (c->fields, iter2, f) {
		if (f->kind == R_BIN_FIELD_KIND_PROPERTY || !f->name) {
			continue;
		}
		const char *fname = r_bin_name_tostring2 (f->name, pref);
		if (R_STR_ISEMPTY (fname) || !strcmp (fname, "isa")) {
			continue;
		}
		char *type = objc_decl_type (f->type? r_bin_name_tostring2 (f->type, pref): NULL, NULL);
		if (!has_ivars) {
			r_cons_println (core->cons, "{");
			has_ivars = true;
		}
		if (type) {
			r_cons_printf (core->cons, "\t%s %s;\n", type, fname);
		}
		free (type);
	}
	if (has_ivars) {
		r_cons_println (core->cons, "}");
	}
	r_list_foreach (c->fields, iter2, f) {
		if (f->kind != R_BIN_FIELD_KIND_PROPERTY || !f->name) {
			continue;
		}
		const char *fname = r_bin_name_tostring2 (f->name, pref);
		if (R_STR_ISEMPTY (fname) || objc_is_builtin_property_name (fname)) {
			continue;
		}
		bool is_object = false;
		char *type = objc_guess_property_type (c, fname, pref, &is_object);
		if (type) {
			const char *attr = is_object? "nonatomic, strong": "nonatomic, assign";
			if (!strcmp (type, "id")) {
				attr = "nonatomic, strong";
			}
			r_cons_printf (core->cons, "@property (%s) %s %s;\n", attr, type, fname);
		}
		free (type);
	}
	r_list_foreach (c->methods, iter3, sym) {
		const char *sname = r_bin_name_tostring2 (sym->name, pref);
		bool is_class_method = (sym->attr & R_BIN_ATTR_CLASS) != 0;
		if (!is_class_method && sym->type) {
			is_class_method = !r_str_startswith (sym->type, R_BIN_TYPE_METH_STR);
		}
		char *ret = objc_method_return_type (c, sname, sym, pref);
		char *decl = objc_method_decl (c, sname, ret? ret: "id", is_class_method, pref);
		if (decl) {
			r_cons_printf (core->cons, "%s\n", decl);
		}
		free (decl);
		free (ret);
	}
	r_cons_printf (core->cons, "@end\n");
}
