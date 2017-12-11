/* sdb - MIT - Copyright 2017 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "sdb.h"

mht *mht_new(ut32 size, mht_freecb f) {
	mht *m = calloc(1, sizeof (mht));
	mht_init (m, size, f);
	return m;
}

void mht_init(mht *m, ut32 size, mht_freecb f) {
	if (m) {
		memset(m, 0, sizeof (mht));
		if (size > 0) {
			m->table = calloc (size, sizeof (mhtkv));
			m->size = size;
		}
		m->f = f;
	}
}

void mht_fini(mht *m) {
	ut32 i;
	if (m) {
		if (m->f) {
			for (i = 0; i < m->size; i++) {
				mhtkv *kv = m->table[i];
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
		mht_init(m, 0, NULL);
	}
}

void mht_free(mht *m) {
	mht_fini(m);
	free (m);
}

mhti mht_hash(const char *s) {
	return (mhti)sdb_hash(s);
}

bool mht_set(mht *m, mhti k, mhti v, void *u) {
	if (!m || !m->size || k == MHTNO) {
		return false;
	}
	const int bucket = k % m->size;
	mhtkv *kv = m->table[bucket];
	if (!kv) {
		kv = calloc (sizeof(mhtkv), 2);
		if (kv) {
			m->table[bucket] = kv;
			kv->k = MHTNO;
			kv->v = MHTNO;
			kv->u = NULL;
			return mht_set(m, k, v, u);
		}
		return false;
	}
	mhtkv *tmp = kv;
	while (kv->k != MHTNO) {
		if (kv->k == k) {
			kv->v = v;
			kv->u = u;
			return true;
		}
		kv++;
	}
	int cursz = (kv - tmp);
	int curln = cursz / sizeof(mhtkv);
	mhtkv *newkv = realloc(tmp, (curln + 2) * sizeof(mhtkv));
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

mhtkv *mht_getr(mht *m, mhti k) {
	int bucket = k % m->size;
	mhtkv *kv = m->table[bucket];
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

mhti mht_get(mht *m, mhti k) {
	mhtkv *kv = mht_getr(m, k);
	return kv? kv->v: MHTNO;
}

void *mht_getu(mht *m, mhti k) {
	mhtkv *kv = mht_getr(m, k);
	return kv? kv->u: NULL;
}

bool mht_add(mht *m, mhti k, mhti v, void *u) {
	return mht_getr(m, k)
		? mht_set(m, k, v, u)
		: false;
}

bool mht_del(mht *m, mhti k) {
	int bucket = k % m->size;
	if (k == MHTNO) {
		return false;
	}
	mhtkv *kv = m->table[bucket];
	if (kv) {
		while (kv->k != MHTNO) {
			if (kv->k == k) {
				if (m->f) {
					m->f (kv->u);
				}
				mhtkv *n = kv + 1;
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
static char *mht_str(mht *m, mhti k) {
	// walk all buckets and print the data..... we need a printer for kv->u
	char *res = malloc (1024);
	int bucket = k % m->size;
	mhti *kv = m->table[bucket];
	char *p = res;
	for (i = 0; i < 1024; i++) {
		sprintf (p, "%s%lld", comma, kv->v);
		p += strlen (p);
		kv++;
	}
	return res;
}

static char *mht_str(mht *m) {
	char *res = malloc (1024);
	int bucket = k % m->size;
	mhti *kv = m->table[bucket];
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
	mht m;
	mht_init(&m, 32, free);
	mht_set(&m, mht_hash("username"), 1024, NULL);
	mht_set(&m, 32, 212, strdup("test"));
	mht_del(&m, mht_hash("username"));
	printf ("%d\n", (int)mht_get(&m, mht_hash("username")));
	printf ("%s\n", mht_getu(&m, 32)); //mht_hash("username")));
	mht_fini(&m);
	return 0;
}
#endif
