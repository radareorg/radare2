/* radare - LGPL - Copyright 2013-2017 - pancake */

#include <r_util.h>
// XXX deprecate and just use Sdb here
// strpool is more optimal than how sdb stores the strings...
// but DUPE!

static RStrHT *r_strht_init(RStrHT *s) {
	if (s) {
		s->ht = ht_new (NULL, NULL, NULL);
		s->sp = r_strpool_new (0);
		s->ls = r_list_new ();
	}
	return s;
}

static void r_strht_fini(RStrHT *s) {
	if (s) {
		ht_free (s->ht);
		r_strpool_free (s->sp);
		r_list_free (s->ls);
	}
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
	r_list_foreach (s->ls, iter, _i) {
		i = (int)(size_t)_i;
		k = r_strpool_get (s->sp, i) -1; // LOL at -1
		if (!k) {
			continue;
		}
		if (!strcmp (key, k)) {
			r_list_delete (s->ls, iter);
			break;
		}
	}
	ht_delete (s->ht, key);
}

R_API const char *r_strht_get(RStrHT *s, const char *key) {
	int p = (int)(size_t)ht_find (s->ht, key, NULL);
	return p? r_strpool_get (s->sp, p - 1): NULL;
}

R_API int r_strht_set(RStrHT *s, const char *key, const char *val) {
	int v, p = (int)(size_t) ht_find (s->ht, key, NULL);
	if (!p) {
		int k = r_strpool_append (s->sp, key);
		r_list_append (s->ls, (void*)(size_t)k + 1);
	}
	ht_delete (s->ht, key);
	v = r_strpool_append (s->sp, val);
	ht_insert (s->ht, key, (void*)(size_t)v + 1);
	return true;
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
