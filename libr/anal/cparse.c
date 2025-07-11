/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_anal.h>

R_IPI char* kvc_parse(const char* header_content, char **errmsg);

static RAnalPlugin *resolve_plugin (RAnal *anal, int type) {
	RAnalPlugin *p;
	RListIter *iter;
	const char *tpp = anal->opt.tparser;
	r_list_foreach (anal->plugins, iter, p) {
		if (!strcmp (tpp, p->meta.name)) {
			switch (type) {
			case 0:
				if (p->tparse_text) {
					return p;
				}
				break;
			case 1:
				if (p->tparse_file) {
					return p;
				}
				break;
			}
		}
	}
	return NULL;
}

R_API char *r_anal_cparse2(RAnal *anal, const char *code, char **error_msg) {
	return kvc_parse (code, error_msg);
}

R_API char *r_anal_cparse_file(RAnal *anal, const char *path, const char *dir, char **error_msg) {
	if (anal->opt.tparser) {
		RAnalPlugin *p = resolve_plugin (anal, 1);
		if (p) {
			return p->tparse_file (anal, path, dir);
		} else {
			RAnalPlugin *p = resolve_plugin (anal, 0);
			if (p) {
				char *text = r_file_slurp (path, NULL);
				char *res = p->tparse_text (anal, text);
				free (text);
				return res;
			}
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
	if (anal->opt.tparser) {
		RAnalPlugin *p = resolve_plugin (anal, 0);
		if (p) {
			return p->tparse_text(anal, code);
		}
	}
	return r_anal_cparse2 (anal, code, error_msg);
}
