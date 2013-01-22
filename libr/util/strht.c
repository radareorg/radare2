/* radare - LGPL - Copyright 2013 - pancake */

#include <r_util.h>

static void r_strht_init(RStrHT *s) {
	s->ht = r_hashtable_new ();
	s->sp = r_strpool_new (0);
	s->ls = r_list_new ();
}

static void r_strht_fini(RStrHT *s) {
	r_hashtable_free (s->ht);
	r_strpool_free (s->sp);
	r_list_free (s->ls);
}

R_API RStrHT *r_strht_new() {
	RStrHT *s = R_NEW0 (RStrHT);
	r_strht_init (s);
	return s;
}

R_API void r_strht_free(RStrHT *s) {
	r_strht_fini (s);
	free (s);
}

R_API void r_strht_del(RStrHT *s, const char *key) {
	int i, *_i;
	const char *k;
	RListIter *iter;
	ut32 h = r_str_hash (key);
	r_hashtable_remove (s->ht, h);
	r_list_foreach (s->ls, iter, _i) {
		i = (int)(size_t)_i;
		k = r_strpool_get (s->sp, i);
		if (!strcmp (key, k)) {
			r_list_delete (s->ls, iter);
			break;
		}
	}
}

R_API const char *r_strht_get(RStrHT *s, const char *key) {
	ut32 h = r_str_hash (key);
	int p = (int)(size_t)r_hashtable_lookup (s->ht, h);
	if (p) return r_strpool_get (s->sp, p-1);
	return NULL;
}

R_API int r_strht_set(RStrHT *s, const char *key, const char *val) {
	ut32 h = r_str_hash (key);
	int v, p = (int)(size_t) r_hashtable_lookup (s->ht, h);
	if (!p) {
		int k = r_strpool_append (s->sp, key);
		r_list_append (s->ls, (void*)(size_t)k+1);
	}
	r_hashtable_remove (s->ht, h);
	v = r_strpool_append (s->sp, val);
	r_hashtable_insert (s->ht, h, (void*)(size_t)v+1);
	return R_TRUE;
}

R_API void r_strht_clear(RStrHT *s) {
	r_strht_fini (s);
	r_strht_init (s);
}

#if MAIN
main() {
	RStrHT *h = r_strht_new ();
	r_strht_set (h, "foo", "hello world");
	printf ("%s\n", r_strht_get (h, "foo"));
	r_strht_free (h);
}
#endif
