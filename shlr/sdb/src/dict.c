/* sdb - MIT - Copyright 2017 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "sdb.h"

dict *dict_new(ut32 size, dict_freecb f) {
	dict *m = calloc (1, sizeof (dict));
	dict_init (m, size, f);
	return m;
}

void dict_init(dict *m, ut32 size, dict_freecb f) {
	if (m) {
		memset (m, 0, sizeof (dict));
		if (size > 0) {
			m->table = calloc (size, sizeof (dictkv));
			m->size = size;
		}
		m->f = f;
	}
}

void dict_fini(dict *m) {
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

void dict_free(dict *m) {
	dict_fini(m);
	free (m);
}

// collisions are not handled in a dict. use a hashtable if you want to use strings as keys.
dicti dict_hash(const char *s) {
	return (dicti)sdb_hash(s);
}

bool dict_set(dict *m, dicti k, dicti v, void *u) {
	if (!m || !m->size || k == MHTNO) {
		return false;
	}
	const int bucket = k % m->size;
	dictkv *kv = m->table[bucket];
	if (!kv) {
		kv = calloc (sizeof(dictkv), 2);
		if (kv) {
			m->table[bucket] = kv;
			kv->k = MHTNO;
			kv->v = MHTNO;
			kv->u = NULL;
			return dict_set(m, k, v, u);
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
	int cursz = (kv - tmp);
	int curln = cursz / sizeof(dictkv);
	dictkv *newkv = realloc(tmp, (curln + 2) * sizeof(dictkv));
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
		return false;
	}
	return true;
}

dictkv *dict_getr(dict *m, dicti k) {
	int bucket = k % m->size;
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

dicti dict_get(dict *m, dicti k) {
	dictkv *kv = dict_getr(m, k);
	return kv? kv->v: MHTNO;
}

void *dict_getu(dict *m, dicti k) {
	dictkv *kv = dict_getr(m, k);
	return kv? kv->u: NULL;
}

bool dict_add(dict *m, dicti k, dicti v, void *u) {
	return dict_getr(m, k)
		? dict_set(m, k, v, u)
		: false;
}

bool dict_del(dict *m, dicti k) {
	int bucket = k % m->size;
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
	dict_init(&m, 32, free);
	dict_set(&m, dict_hash("username"), 1024, NULL);
	dict_set(&m, 32, 212, strdup("test"));
	dict_del(&m, dict_hash("username"));
	printf ("%d\n", (int)dict_get(&m, dict_hash("username")));
	printf ("%s\n", dict_getu(&m, 32)); //dict_hash("username")));
	dict_fini(&m);
	return 0;
}
#endif
