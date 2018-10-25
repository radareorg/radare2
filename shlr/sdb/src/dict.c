/* sdb - MIT - Copyright 2017 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "sdb.h"

SDB_API dict *dict_new(ut32 size, dict_freecb f) {
	dict *m = calloc (1, sizeof (dict));
	if (!dict_init (m, R_MAX (size, 1), f)) {
		free (m);
		m = NULL;
	}
	return m;
}

// maybe internal?
static ut32 dict_bucket(dict *m, dicti k) {
	if (m->size > 0) {
		return k % m->size;
	}
	return 0;
}

SDB_API bool dict_init(dict *m, ut32 size, dict_freecb f) {
	if (m) {
		memset (m, 0, sizeof (dict));
		if (size > 0) {
			m->table = calloc (size, sizeof (dictkv));
			if (!m->table) {
				return false;
			}	
			m->size = size;
		}
		m->f = f;
	}
	return true;
}

SDB_API void dict_fini(dict *m) {
	ut32 i;
	if (m) {
		if (m->f) {
			for (i = 0; i < m->size; i++) {
				dictkv *kv = m->table[i];
				if (kv) {
					while (kv->k != MHTNO) {
						m->f(kv->u);
						kv++;
					}
				}
				free (m->table[i]);
			}
		} else {
			for (i = 0; i < m->size; i++) {
				free (m->table[i]);
			}
		}
		free (m->table);
		dict_init(m, 0, NULL);
	}
}

SDB_API void dict_free(dict *m) {
	dict_fini(m);
	free (m);
}

// collisions are not handled in a dict. use a hashtable if you want to use strings as keys.
SDB_API dicti dict_hash(const char *s) {
	return (dicti)sdb_hash(s);
}

SDB_API bool dict_set(dict *m, dicti k, dicti v, void *u) {
	if (!m || !m->size || k == MHTNO) {
		return false;
	}
	const int bucket = dict_bucket (m, k);
	dictkv *kv = m->table[bucket];
	if (!kv) {
		kv = calloc (sizeof (dictkv), 2);
		if (kv) {
			m->table[bucket] = kv;
			kv->k = MHTNO;
			kv->v = MHTNO;
			kv->u = NULL;
			return dict_set (m, k, v, u);
		}
		return false;
	}
	dictkv *tmp = kv;
	while (kv->k != MHTNO) {
		if (kv->k == k) {
			kv->v = v;
			kv->u = u;
			return true;
		}
		kv++;
	}
	int curln = (kv - tmp);
	dictkv *newkv = realloc (tmp, (curln + 2) * sizeof (dictkv));
	if (newkv) {
		kv = m->table[bucket] = newkv;
		kv += curln;
		kv->k = k;
		kv->v = v;
		kv->u = u;
		kv++;
		kv->k = MHTNO;
		kv->v = MHTNO;
		kv->u = NULL;
		return true;
	}
	return false;
}

SDB_API void dict_stats(dict *m) {
	ut32 i, j;
	for (i = 0; i < m->size; i++) {
		printf ("%d: ", i);
		j = 0;
		dictkv *kv = m->table[i];
		if (kv) {
			while (kv->k != MHTNO) {
				j++;
				kv++;
			}
		}
		printf ("%d\n", j);
	}
}

SDB_API dictkv *dict_getr(dict *m, dicti k) {
	if (!m->size) {
		return NULL;
	}
	int bucket = dict_bucket (m, k);
	dictkv *kv = m->table[bucket];
	if (kv) {
		while (kv->k != MHTNO) {
			if (kv->k == k) {
				return kv;
			}
			kv++;
		}
	}
	return NULL;
}

SDB_API dicti dict_get(dict *m, dicti k) {
	dictkv *kv = dict_getr (m, k);
	return kv? kv->v: MHTNO;
}

SDB_API void *dict_getu(dict *m, dicti k) {
	dictkv *kv = dict_getr (m, k);
	return kv? kv->u: NULL;
}

SDB_API bool dict_add(dict *m, dicti k, dicti v, void *u) {
	return dict_getr(m, k)
		? dict_set(m, k, v, u)
		: false;
}

SDB_API bool dict_del(dict *m, dicti k) {
	int bucket = dict_bucket (m, k);
	if (k == MHTNO) {
		return false;
	}
	dictkv *kv = m->table[bucket];
	if (kv) {
		while (kv->k != MHTNO) {
			if (kv->k == k) {
				if (m->f) {
					m->f (kv->u);
				}
				dictkv *n = kv + 1;
				while (n->k != MHTNO) {
					*kv++ = *n++;
				}
				kv->k = MHTNO;
				return true;
			}
			kv++;
		}
	}
	return false;
}

// call the cb callback on each element of the dictionary
// m : dict to iterate
// cb : function that accept a dictkv. When it returns a value != 0, the
//      iteration stops
// u : additional information to pass to cb together with the dictkv
SDB_API void dict_foreach(dict *m, dictkv_cb cb, void *u) {
	bool iterate = true;
	ut32 i;

	for (i = 0; i < m->size && iterate; i++) {
		dictkv *kv = m->table[i];
		if (kv) {
			while (kv->k != MHTNO) {
				int res = cb (kv, u);
				if (res != 0) {
					iterate = false;
					break;
				}
				kv++;
			}
		}
	}
}

#if 0
static char *dict_str(dict *m, dicti k) {
	// walk all buckets and print the data..... we need a printer for kv->u
	char *res = malloc (1024);
	int bucket = k % m->size;
	dicti *kv = m->table[bucket];
	char *p = res;
	for (i = 0; i < 1024; i++) {
		sprintf (p, "%s%lld", comma, kv->v);
		p += strlen (p);
		kv++;
	}
	return res;
}

static char *dict_str(dict *m) {
	char *res = malloc (1024);
	int bucket = k % m->size;
	dicti *kv = m->table[bucket];
	int i;
	char *p = res;
	for (i = 0; i < m->size; i++) {
		sprintf (p, "%s%lld", comma, kv->v);
		p += strlen (p);
		kv++;
	}
	return res;
}

int main() {
	dict m;
	dict_init (&m, 2, free);
	dict_set (&m, 0x100, 1, NULL);
	dict_set (&m, 0x200, 2, NULL);
	dict_set (&m, 0x300, 3, NULL);
	dict_set (&m, 0x400, 4, NULL);
printf ("%d %d\n", (int)dict_get(&m, 0x100), (int)dict_get(&m, 0x200));
printf ("%d %d\n", (int)dict_get(&m, 0x300), (int)dict_get(&m, 0x400));
dict_stats(&m);

#if 0
	dict_set(&m, dict_hash("username"), 1024, NULL);
	dict_set(&m, 32, 212, strdup("test"));
	dict_del(&m, dict_hash("username"));
	printf ("%d\n", (int)dict_get(&m, dict_hash("username")));
	printf ("%s\n", dict_getu(&m, 32)); //dict_hash("username")));
#endif
	dict_fini(&m);
	return 0;
}
#endif
