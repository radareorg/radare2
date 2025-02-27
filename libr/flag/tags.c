/* radare - LGPL - Copyright 2018-2025 - pancake */

#include <r_flag.h>

R_API RList *r_flag_tags_set(RFlag *f, const char *name, const char *words) {
	R_RETURN_VAL_IF_FAIL (f && name && words, NULL);
	r_strf_var (k, 64, "tag.%s", name);
	sdb_set (f->tags, k, words, -1);
	return NULL;
}

R_API RList *r_flag_tags_list(RFlag *f, R_NULLABLE const char *name) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	if (name) {
		r_strf_var (k, 64, "tag.%s", name);
		char *words = sdb_get (f->tags, k, NULL);
		return r_str_split_list (words, " ", 0);
	}
	RList *res = r_list_newf (free);
	SdbList *o = sdb_foreach_list (f->tags, false);
	SdbListIter *iter;
	SdbKv *kv;
	ls_foreach (o, iter, kv) {
		const char *tag = sdbkv_key (kv);
		if (r_str_nlen (tag, 6) < 5) {
			continue;
		}
		r_list_append (res, (void *)strdup (tag + 4));
	}
	ls_free (o);
	return res;
}

R_API void r_flag_tags_reset(RFlag *f, R_NULLABLE const char *name) {
	R_RETURN_IF_FAIL (f);
	if (name) {
		r_strf_var (k, 64, "tag.%s", name);
		sdb_unset (f->tags, k, 0);
	} else {
		sdb_reset (f->tags);
	}
}

struct iter_glob_flag_t {
	RList *res;
	RList *words;
};

static bool iter_glob_flag(RFlagItem *fi, void *user) {
	struct iter_glob_flag_t *u = (struct iter_glob_flag_t *)user;
	RListIter *iter;
	const char *word;

	r_list_foreach (u->words, iter, word) {
		if (r_str_glob (fi->name, word)) {
			r_list_append (u->res, fi);
		}
	}
	return true;
}

R_API RList *r_flag_tags_get(RFlag *f, const char *name) {
	R_RETURN_VAL_IF_FAIL (f && name, NULL);
	r_strf_var (k, 64, "tag.%s", name);
	RList *res = r_list_newf (NULL);
	char *words = sdb_get (f->tags, k, NULL);
	if (words) {
		RList *list = r_str_split_list (words, " ",  0);
		struct iter_glob_flag_t u = { .res = res, .words = list };
		r_flag_foreach (f, iter_glob_flag, &u);
		r_list_free (list);
		free (words);
	}
	return res;
}
