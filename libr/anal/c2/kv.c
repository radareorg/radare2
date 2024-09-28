#include <r_util.h>

typedef struct {
	char attr_keys[10][256];
	char attr_values[10][256];
	int count;
} AttrList;

static void parse_attributes(const char **pp, AttrList *attrs) {
	const char *p = *pp;
	attrs->count = 0;
	while (isspace((ut8)*p)) p++;
	while (*p == '@') {
		p++;
		const char *attr_start = p;
		while (isalnum((ut8)*p) || *p == '_') p++;
		size_t attr_len = p - attr_start;
		char attr_name[256];
		strncpy(attr_name, attr_start, attr_len);
		attr_name[attr_len] = '\0';

		char attr_value[256] = "true";
		if (*p == '(') {
			p++;
			const char *value_start = p;
			while (*p && *p != ')') p++;
			size_t value_len = p - value_start;
			strncpy(attr_value, value_start, value_len);
			attr_value[value_len] = '\0';
			if (*p == ')') p++;
		}
		strncpy(attrs->attr_keys[attrs->count], attr_name, 256);
		strncpy(attrs->attr_values[attrs->count], attr_value, 256);
		attrs->count++;
		while (isspace((ut8)*p)) p++;
	}
	*pp = p;
}

static void apply_attributes(RStrBuf *sb, const char *type, const char *scope, AttrList *attrs) {
	for (int i = 0; i < attrs->count; i++) {
		r_strbuf_appendf (sb, "%s.%s.@.%s=%s\n", type, scope, attrs->attr_keys[i], attrs->attr_values[i]);
	}
	attrs->count = 0; // Reset after applying
}

static inline const char *skip_spaces(const char *p) {
	while (isspace ((ut8)*p)) {
		p++;
	}
	return p;
}

static bool parse_member_typename(const char *b, const char *e, char **name, char **type, char **dimensions) {
	const char *d = NULL;
	*dimensions = NULL;
	if (e > b && e[-1] == ']') {
		d = e - 1;
		do {
			d--;
		} while (*d != '[');
		e = d;
		*dimensions = r_str_ndup (d + 1, e - d + 2);
	}
	const char *name_begin = e - 1;
	while (*name_begin && !isspace (*name_begin) && *name_begin != '*') {
		name_begin--;
	}
	name_begin++;
	*name = r_str_ndup (name_begin, e - name_begin);
	*type = r_str_ndup (b, name_begin - b);
	r_str_trim (*name);
	r_str_trim (*type);
	return true;
}

static const char *skip_until_semicolon (const char *p) {
	while (*p && *p != ';') p++;
	if (*p == ';') p++;
	return p;
}

static bool parse_struct(const char *type, const char **pp, RStrBuf *sb, AttrList *attrs) {
	const char *p = *pp;
	char struct_name[256] = "";
	// AttrList attrs = { .count = 0 };
	p = skip_spaces (p);
	const char *name_start = p;
	while (isalnum((ut8)*p) || *p == '_') {
		p++;
	}
	size_t name_len = p - name_start;
	if (name_len > 0) {
		strncpy (struct_name, name_start, name_len);
		struct_name[name_len] = '\0';
	}
	p = skip_spaces (p);
	RStrBuf *args_sb = r_strbuf_new ("");
	if (*p == '{') {
		p++;
		if (attrs->count > 0) {
			apply_attributes (sb, type, struct_name, attrs);
		}
		int member_idx = 0;
		while (*p && *p != '}') {
			p = skip_spaces (p);
			if (r_str_startswith (p, "///")) {
				p += 3;
				parse_attributes (&p, attrs);
			}
			char *member_name = NULL;
			char *member_type = NULL;
			char *dimensions = NULL;

			const char *type_start = p;
			const char *semicolon = type_start;
			while (*semicolon && *semicolon != ';') {
				semicolon++;
			}
			const char *name_end = NULL;
			if (*semicolon == ';') {
				const char *type_end = semicolon;
				parse_member_typename (type_start, type_end, &member_name, &member_type, &dimensions);
				p = skip_spaces (type_end + 1);
			} else {
				// ERROR HERE
				R_LOG_ERROR ("Missing semicolon");
				return false;
			}
			char array_info[256] = "";
			char full_scope[512];
			snprintf(full_scope, sizeof(full_scope), "%s.%s", struct_name, member_name);
			if (dimensions) {
				r_strbuf_appendf (sb, "%s.%s=%s,0,%s\n", type, full_scope, member_type, dimensions? dimensions:"");
			} else {
				r_strbuf_appendf (sb, "%s.%s=%s\n", type, full_scope, member_type);
			}
			if (attrs->count > 0) {
				apply_attributes (sb, type, full_scope, attrs);
			}
			free (dimensions);
			r_strbuf_appendf (args_sb, "%s%s", member_idx?",":"", member_name);
			member_idx++;
		}
		if (*p == '}') {
			p++;
		}
		p = skip_until_semicolon (p);
	}
	char *argstr = r_strbuf_drain (args_sb);
	r_strbuf_appendf (sb, "%s.%s=%s\n", type, struct_name, argstr);
	free (argstr);
	r_strbuf_appendf (sb, "%s=%s\n", struct_name, type);
	*pp = p;
	return true;
}

static void parse_enum(const char **pp, RStrBuf *sb, AttrList *attrs) {
	const char *p = *pp;
	char enum_name[256] = "";
	while (isspace((ut8)*p)) p++;
	const char *name_start = p;
	while (isalnum((ut8)*p) || *p == '_') p++;
	size_t name_len = p - name_start;
	if (name_len > 0) {
		strncpy (enum_name, name_start, name_len);
		enum_name[name_len] = '\0';
	}
	while (isspace ((ut8)*p)) {
		p++;
	}
	if (*p == '{') {
		p++;
		int value = 0;
		while (*p && *p != '}') {
			while (isspace((ut8)*p)) p++;
			if (strncmp(p, "///", 3) == 0) {
				p += 3;
				parse_attributes(&p, attrs);
			}
			const char *name_start = p;
			while (isalnum((ut8)*p) || *p == '_') p++;
			size_t name_len = p - name_start;
			if (name_len == 0) break;
			char member_name[256];
			strncpy(member_name, name_start, name_len);
			member_name[name_len] = '\0';

			while (isspace((ut8)*p)) p++;
			if (*p == '=') {
				p++;
				while (isspace((ut8)*p)) p++;
				const char *value_start = p;
				while (isalnum((ut8)*p) || *p == '_' || *p == '+' || *p == '-') p++;
				size_t value_len = p - value_start;
				char value_str[256];
				strncpy(value_str, value_start, value_len);
				value_str[value_len] = '\0';
				value = atoi(value_str);
			}
			char full_scope[512];
			snprintf(full_scope, sizeof(full_scope), "%s.%s", enum_name, member_name);
			if (attrs->count > 0) {
				apply_attributes (sb, "enum", enum_name, attrs);
			}
			r_strbuf_appendf(sb, "enum.%s=%d\n", full_scope, value);
			value++;
			while (isspace((ut8)*p)) p++;
			if (*p == ',') p++;
		}
		if (*p == '}') p++;
		while (*p && *p != ';') p++;
		if (*p == ';') p++;
		if (attrs->count > 0) {
			apply_attributes (sb, "enum", enum_name, attrs);
		}
		r_strbuf_appendf(sb, "%s=enum\n", enum_name);
	}
	*pp = p;
}

static const char *find_param_end(const char *p) {
	while (*p && *p != ',' && *p != ')') {
		p++;
	}
	return p;
}

static bool parse_param(const char *b, const char *e, char **name, char **type) {
	char *s = r_str_ndup (b, e - b);
	const char *name_begin = e - 1;
	while (*name_begin && !isspace (*name_begin) && *name_begin != '*') {
		name_begin--;
	}
	name_begin++;
	*name = r_str_ndup (name_begin, e - name_begin);
	*type = r_str_ndup (b, name_begin - b);
	r_str_trim (*name);
	r_str_trim (*type);
	return true;
}

static void parse_function(const char **pp, RStrBuf *sb, AttrList *attrs) {
	const char *p = *pp;
	if (r_str_startswith (p, "///")) {
		p += 3;
		parse_attributes (&p, attrs);
	}
	const char *par = p;
	while (*par && *par != '(') {
		par++;
	}
	char *return_type = NULL;
	char *func_name = NULL;
	if (*par == '(') {
		const char *name_end = par;
		par--;
		while (isspace (*par)) {
			par--;
		}
		while (!isspace (*par)) {
			par--;
		}
		par++;
		const char *name_begin = par;
		func_name = r_str_ndup (name_begin, name_end - name_begin);
		r_str_trim (func_name);
		const char *type_start = p;
		return_type = r_str_ndup (type_start, name_begin -type_start);
		r_str_trim (return_type);
		p = name_end;
	}

	RStrBuf *func_args_sb = r_strbuf_new ("");
	while (isspace((ut8)*p)) p++;
	if (*p == '(') {
		p++;
		// Parse parameters
		const char *params_start = p;
		int paren_level = 1;
		char params[1024] = {0};
		size_t params_len = 0;
		while (*p && paren_level > 0) {
			if (*p == '(') paren_level++;
			if (*p == ')') paren_level--;
			if (paren_level > 0) {
				params[params_len++] = *p;
			}
			p++;
		}
		params[params_len] = '\0';

		// Now parse the parameters
		const char *param_p = params;
		int arg_idx = 0;
		while (*param_p) {
			const char *param_begin = param_p;
			const char *param_end = find_param_end (param_p);
			char *param_name = NULL;
			char *param_type = NULL;
			parse_param (param_begin, param_end, &param_name, &param_type);
			param_p = param_end + 1;
			param_begin = NULL;
			param_end = NULL;
			if (!param_name) {
				// unnamed arguments
				param_name = r_str_newf ("arg%d", arg_idx);
			}
			r_strbuf_appendf(sb, "func.%s.%s=%s\n", func_name, param_name, param_type);
			while (isspace((ut8)*param_p)) param_p++;
			if (*param_p == ',') {
				param_p++;
			}
			r_strbuf_appendf (func_args_sb, "%s%s", arg_idx?",":"", param_name);
			free (param_name);
			arg_idx++;
		}
		// Build func.func_name.return=return_type
		r_strbuf_appendf (sb, "func.%s.return=%s\n", func_name, return_type);

		if (attrs->count > 0) {
			apply_attributes (sb, "func", func_name, attrs);
		}
		while (*p && *p != ';' && *p != '{') p++;
		if (*p == ';' || *p == '{') p++;
	}
	// Build func.func_name=arg0,arg1,...
	char *func_args = r_strbuf_drain (func_args_sb);
	r_strbuf_appendf (sb, "func.%s=%s\n", func_name, func_args);
	r_strbuf_appendf (sb, "%s=func\n", func_name);
	free (func_args);
	*pp = p;
}

char* parse_header(const char* header_content) {
	AttrList attrs = { .count = 0 };
	RStrBuf *sb = r_strbuf_new("");
	const char *p = header_content;
	while (*p) {
		while (isspace((ut8)*p)) { //  || *p == '/' || *p == '*')
			p++;
		}
#if 0
		if (strncmp(p, "typedef", 7) == 0 && isspace((ut8)p[7])) {
			p += 7;
			while (isspace((ut8)*p)) p++;
			continue;
		}
#endif
		if (r_str_startswith (p, "struct") && isspace((ut8)p[6])) {
			p += 6;
			parse_struct ("struct", &p, sb, &attrs);
			continue;
		}
		if (r_str_startswith (p, "union") && isspace((ut8)p[5])) {
			p += 5;
			if (!parse_struct ("union", &p, sb, &attrs)) {
				break;
			}
			continue;
		}
		if (r_str_startswith (p, "enum") && isspace((ut8)p[4])) {
			p += 4;
			parse_enum (&p, sb, &attrs);
			continue;
		}
		if (r_str_startswith (p, "///")) {
			const char *attr_p = p + 3;
			parse_attributes (&attr_p, &attrs);

			const char *func_p = attr_p;
#if 0
			const char *type_start = func_p;
			while (isalnum((ut8)*func_p) || *func_p == '_' || *func_p == '*') {
				func_p++;
			}
			size_t type_len = func_p - type_start;
			if (type_len > 0) {
				while (isspace((ut8)*func_p)) func_p++;
				const char *name_start = func_p;
				while (isalnum((ut8)*func_p) || *func_p == '_') func_p++;
				size_t name_len = func_p - name_start;
				if (name_len > 0) {
					while (isspace((ut8)*func_p)) func_p++;
					if (*func_p == '(') {
						p = attr_p;
						parse_function (&p, sb, &attrs);
						continue;
					}
				}
			}
#endif
			p = func_p;
			continue;
		}
		const char *func_p = p;
		const char *type_start = func_p;
		while (isalnum ((ut8)*func_p) || *func_p == '_' || *func_p == '*') {
			func_p++;
		}
		size_t type_len = func_p - type_start;
		if (type_len > 0) {
			while (*func_p && isspace((ut8)*func_p)) func_p++;
			const char *name_start = func_p;
			while (*func_p && isalnum((ut8)*func_p) || *func_p == '_') func_p++;
			size_t name_len = func_p - name_start;
			if (name_len > 0) {
				while (isspace((ut8)*func_p)) func_p++;
				if (*func_p == '(') {
					parse_function (&p, sb, &attrs);
					continue;
				}
			}
		}
		while (*p && !isspace ((ut8)*p)) p++;
	}
	return r_strbuf_drain (sb);
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <header_file.h>\n", argv[0]);
		return 1;
	}

	char *content = r_file_slurp(argv[1], NULL);
	if (!content) {
		R_LOG_ERROR ("Failed to read file: %s", argv[1]);
		return 1;
	}

	char *result = parse_header((const char *)content);
	if (result) {
		printf("%s\n", result);
		free(result);
	}

	free(content);
	return 0;
}
