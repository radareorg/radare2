/* radare - LGPL - Copyright 2013-2026 - pancake */

#include <r_anal.h>

R_IPI char* kvc_parse(const char* header_content, int ptr_size, char **errmsg);
R_IPI int kvc_type_size(const char *name, int dimension, int ptr_size);
R_IPI int kvc_type_align(const char *name, int ptr_size);

static RAnalPlugin *resolve_plugin (RAnal *anal, int type) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	const char *tpp = anal->opt.tparser;
	RAnalPlugin *p = r_libstore_find_name (anal->libstore, tpp);
	if (p && ((type && p->tparse_file) || p->tparse_text)) {
		return p;
	}
	return NULL;
}

static int cparse_ptr_size(RAnal *anal) {
	const int bits = (anal && anal->config)? anal->config->bits: 0;
	return bits > 0? bits / 8: 8;
}

R_API char *r_anal_cparse2(RAnal *anal, const char *code, char **error_msg) {
	return kvc_parse (code, cparse_ptr_size (anal), error_msg);
}

R_API int r_anal_cparse_typesize(const char *type, int dimension, int ptr_size) {
	R_RETURN_VAL_IF_FAIL (type, 0);
	return kvc_type_size (type, dimension > 0? dimension: 1, ptr_size > 0? ptr_size: 8);
}

R_API int r_anal_cparse_typealign(const char *type, int ptr_size) {
	R_RETURN_VAL_IF_FAIL (type, 1);
	return kvc_type_align (type, ptr_size > 0? ptr_size: 8);
}

R_API char *r_anal_cparse_file(RAnal *anal, const char *path, const char *dir, char **error_msg) {
	if (anal->opt.tparser) {
		RAnalPlugin *p = resolve_plugin (anal, 1);
		if (p) {
			return p->tparse_file (anal, path, dir);
		}
		p = resolve_plugin (anal, 0);
		if (p) {
			char *text = r_file_slurp (path, NULL);
			char *res = p->tparse_text (anal, text);
			free (text);
			return res;
		}
	}
	char *code = r_file_slurp (path, NULL);
	if (code) {
		char *res = r_anal_cparse2 (anal, code, error_msg);
		free (code);
		return res;
	}
	return NULL;
}

R_API char *r_anal_cparse(RAnal *anal, const char *code, char **error_msg) {
	if (anal && anal->opt.tparser) {
		RAnalPlugin *p = resolve_plugin (anal, 0);
		if (p) {
			return p->tparse_text(anal, code);
		}
	}
	return r_anal_cparse2 (anal, code, error_msg);
}
