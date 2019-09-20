/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_parse.h>

#include <mpc.h>

struct r_parse_ctype_t {
	mpc_parser_t *integerlit;
	mpc_parser_t *identifier;
	mpc_parser_t *qualifier;
	mpc_parser_t *pointer;
	mpc_parser_t *array;
	mpc_parser_t *type;
};

#define ALL_PARSERS(ctype) ctype->integerlit, ctype->identifier, ctype->qualifier, ctype->pointer, ctype->array, ctype->type
#define ALL_PARSERS_COUNT 6

static const char *lang =
	"integerlit : /0x[0-9A-Fa-f]+/ | /[0-9]+/;"
	"identifier : (\"struct\" | \"union\" | \"enum\")? /[a-zA-Z_][0-9a-zA-Z_]+/;"
	"qualifier  : \"const\";"
	"pointer    : <qualifier>? '*';"
	"array      : '[' <integerlit> ']';"
	"type       : <qualifier>? <identifier> (<pointer> | <array>)*;";


R_API RParseCType *r_parse_ctype_new() {
	RParseCType *ctype = R_NEW (RParseCType);
	if (!ctype) {
		return NULL;
	}

	ctype->integerlit = mpc_new ("integerlit");
	ctype->identifier = mpc_new ("identifier");
	ctype->qualifier = mpc_new ("qualifier");
	ctype->pointer = mpc_new ("pointer");
	ctype->array = mpc_new ("array");
	ctype->type = mpc_new ("type");

	mpc_err_t *err = mpca_lang (MPCA_LANG_DEFAULT, lang, ALL_PARSERS (ctype), NULL);
	if (err) {
		mpc_err_print (err);
		mpc_err_delete (err);
		r_parse_ctype_free (ctype);
		return NULL;
	}

	return ctype;
}

R_API void r_parse_ctype_free(RParseCType *ctype) {
	if (!ctype) {
		return;
	}
	mpc_cleanup (ALL_PARSERS_COUNT, ALL_PARSERS (ctype));
	free (ctype);
}

static bool is_qualifier_const(mpc_ast_t *a) {
	return strcmp (a->tag, "qualifier|string") == 0
		&& a->contents
		&& strcmp (a->contents, "const") == 0;
}

static bool is_identifier_string(mpc_ast_t *a) {
	return strcmp (a->tag, "identifier|regex") == 0
		&& a->contents;
}

static bool is_identifier_kind(mpc_ast_t *a) {
	return strcmp (a->tag, "identifier|>") == 0
		&& a->children_num == 2
		&& strcmp (a->children[0]->tag, "string") == 0
		&& a->children[0]->contents
		&& strcmp (a->children[1]->tag, "regex") == 0
		&& a->children[1]->contents;
}

static bool is_non_const_pointer(mpc_ast_t *a) {
	return strcmp (a->tag, "pointer|char") == 0
		&& a->contents
		&& strcmp (a->contents, "*") == 0;
}

static bool is_const_pointer(mpc_ast_t *a) {
	return strcmp (a->tag, "pointer|>") == 0
		&& a->children_num == 2
		&& is_qualifier_const (a->children[0])
		&& strcmp (a->children[1]->tag, "char") == 0
		&& a->children[1]->contents
		&& strcmp (a->children[1]->contents, "*") == 0;
}

static bool is_array(mpc_ast_t *a) {
	return strcmp (a->tag, "array|>") == 0
		&& a->children_num == 3
		&& strcmp (a->children[0]->tag, "char") == 0
		&& a->children[0]->contents
		&& strcmp (a->children[0]->contents, "[") == 0
		&& strcmp (a->children[1]->tag, "integerlit|regex") == 0
		&& a->children[1]->contents
		&& strcmp (a->children[2]->tag, "char") == 0
		&& a->children[2]->contents
		&& strcmp (a->children[2]->contents, "]") == 0;
}

static RParseCTypeType *ctype_convert_ast(mpc_ast_t *a) {
	bool is_const = false;
	RParseCTypeType *cur = NULL;
	int i;
	for (i = 0; i < a->children_num; i++) {
		mpc_ast_t *child = a->children[i];

		// const
		if (is_qualifier_const (child)) {
			is_const = true;
		}

		// (struct|union|enum)? <identifier>
		else if (r_str_startswith (child->tag, "identifier|")) {
			if (cur) {
				// identifier should always be the innermost type
				goto beach;
			}
			cur = R_NEW0 (RParseCTypeType);
			if (!cur) {
				goto beach;
			}
			cur->kind = R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER;
			cur->identifier.is_const = is_const;
			cur->identifier.kind = R_PARSE_CTYPE_IDENTIFIER_KIND_UNSPECIFIED;
			if (is_identifier_string (child)) {
				cur->identifier.name = strdup (child->contents);
			} else if (is_identifier_kind (child)) {
				if (strcmp (child->children[0]->contents, "struct") == 0) {
					cur->identifier.kind = R_PARSE_CTYPE_IDENTIFIER_KIND_STRUCT;
				} else if (strcmp (child->children[0]->contents, "union") == 0) {
					cur->identifier.kind = R_PARSE_CTYPE_IDENTIFIER_KIND_UNION;
				} else if (strcmp (child->children[0]->contents, "enum") == 0) {
					cur->identifier.kind = R_PARSE_CTYPE_IDENTIFIER_KIND_ENUM;
				}
				cur->identifier.name = strdup (child->children[1]->contents);
			} else {
				goto beach;
			}
			if (!cur->identifier.name) {
				goto beach;
			}
			is_const = false;
		}

		// <identifier>
		else if (is_identifier_string (child)) {
			if (cur) {
				// identifier should always be the innermost type
				goto beach;
			}
			cur = R_NEW0 (RParseCTypeType);
			if (!cur) {
				goto beach;
			}
			cur->kind = R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER;
			cur->identifier.kind = R_PARSE_CTYPE_IDENTIFIER_KIND_UNSPECIFIED;
			cur->identifier.is_const = is_const;
			cur->identifier.name = strdup (child->contents);
			if (!cur->identifier.name) {
				goto beach;
			}
			is_const = false;
		}

		// *
		else if (is_non_const_pointer (child)) {
			RParseCTypeType *pointer = R_NEW0 (RParseCTypeType);
			if (!pointer) {
				goto beach;
			}
			pointer->kind = R_PARSE_CTYPE_TYPE_KIND_POINTER;
			pointer->pointer.is_const = false;
			pointer->pointer.type = cur;
			cur = pointer;
		}

		// const *
		else if (is_const_pointer (child)) {
			RParseCTypeType *pointer = R_NEW0 (RParseCTypeType);
			if (!pointer) {
				goto beach;
			}
			pointer->kind = R_PARSE_CTYPE_TYPE_KIND_POINTER;
			pointer->pointer.is_const = true;
			pointer->pointer.type = cur;
			cur = pointer;
		}

		// <array>
		else if (is_array (child)) {
			RParseCTypeType *array = R_NEW0 (RParseCTypeType);
			if (!array) {
				goto beach;
			}
			array->kind = R_PARSE_CTYPE_TYPE_KIND_ARRAY;
			array->array.count = strtoull (child->children[1]->contents, NULL, 0);
			array->array.type = cur;
			cur = array;
		}

		else {
			goto beach;
		}
	}

	return cur;
beach:
	r_parse_ctype_type_free (cur);
	return NULL;
}

R_API RParseCTypeType *r_parse_ctype_parse(RParseCType *ctype, const char *str, char **error) {
	mpc_result_t r;
	if (mpc_parse ("<string>", str, ctype->type, &r)) {
		RParseCTypeType *ret = ctype_convert_ast (r.output);
		if (error) {
			*error = !ret ? strdup ("internal error") : NULL;
		}
		mpc_ast_delete (r.output);
		return ret;
	} else {
		if (error) {
			*error = mpc_err_string (r.error);
		}
		mpc_err_delete (r.error);
		return NULL;
	}
}

R_API void r_parse_ctype_type_free(RParseCTypeType *type) {
	if (!type) {
		return;
	}
	switch (type->kind) {
	case R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER:
		free (type->identifier.name);
		break;
	case R_PARSE_CTYPE_TYPE_KIND_POINTER:
		r_parse_ctype_type_free (type->pointer.type);
		break;
	case R_PARSE_CTYPE_TYPE_KIND_ARRAY:
		r_parse_ctype_type_free (type->array.type);
		break;
	}
	free (type);
}