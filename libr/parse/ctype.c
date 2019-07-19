/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_parse.h>

#include <mpc.h>

typedef struct r_parse_ctype_t {
	mpc_parser_t *integerlit;
	mpc_parser_t *identifier;
	mpc_parser_t *qualifier;
	mpc_parser_t *pointer;
	mpc_parser_t *array;
	mpc_parser_t *type;
} RParseCType;

#define ALL_PARSERS(ctype) ctype->integerlit, ctype->identifier, ctype->qualifier, ctype->pointer, ctype->array, ctype->type
#define ALL_PARSERS_COUNT 6

static const char *lang =
	"integerlit : /0x[0-9A-Fa-f]+/ | /[0-9]+/;"
	"identifier : /[a-zA-Z_][0-9a-zA-Z_]+/;"
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

		// <identifier>
		else if (strcmp (child->tag, "identifier|regex") == 0
			&& child->contents) {
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
			cur->identifier.name = strdup (child->contents);
			if (!cur->identifier.name) {
				goto beach;
			}
			is_const = false;
		}

		// *
		else if (strcmp (child->tag, "pointer|char") == 0
				&& child->contents
				&& strcmp (child->contents, "*") == 0) { // *
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
		else if (strcmp (child->tag, "pointer|>") == 0
				&& child->children_num == 2
				&& is_qualifier_const (child->children[0])
				&& strcmp (child->children[1]->tag, "char") == 0
				&& child->children[1]->contents
				&& strcmp (child->children[1]->contents, "*") == 0) {
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
		else if (strcmp (child->tag, "array|>") == 0
				&& child->children_num == 3
				&& strcmp (child->children[0]->tag, "char") == 0
				&& child->children[0]->contents
				&& strcmp (child->children[0]->contents, "[") == 0
				&& strcmp (child->children[1]->tag, "integerlit|regex") == 0
				&& child->children[1]->contents
				&& strcmp (child->children[2]->tag, "char") == 0
				&& child->children[2]->contents
				&& strcmp (child->children[2]->contents, "]") == 0) {
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