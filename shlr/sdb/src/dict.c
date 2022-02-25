/* sdb - MIT - Copyright 2017-2022 - pancake */

#include "sdb.h"

SDB_API dict *dict_new(ut32 size, dict_freecb f) {
	dict *m = (dict *)calloc (1, sizeof (dict));
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
			m->table = (void **)calloc (size, sizeof (dictkv));
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
	if (m) {
		ut32 i;
		if (m->f) {
			for (i = 0; i < m->size; i++) {
				dictkv *kv = (dictkv *)m->table[i];
				if (kv) {
					while (kv->k != 0) {
						m->f (kv->u);
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
		dict_init (m, 0, NULL);
	}
}

SDB_API void dict_free(dict *m) {
	if (m) {
		dict_fini (m);
		free (m);
	}
}

// collisions are not handled in a dict. use a hashtable if you want to use strings as keys.
SDB_API dicti dict_hash(const char *s) {
	return (dicti)sdb_hash (s);
}

SDB_API bool dict_set(dict *m, dicti k, dicti v, void *u) {
	if (!m || !m->size || k == 0) {
		return false;
	}
	const int bucket = dict_bucket (m, k);
	dictkv *kv = (dictkv *)m->table[bucket];
	if (!kv) {
		kv = (dictkv *)calloc (sizeof (dictkv), 2);
		if (kv) {
			m->table[bucket] = kv;
			kv->k = 0;
			kv->v = 0;
			kv->u = NULL;
			return dict_set (m, k, v, u);
		}
		return false;
	}
	dictkv *tmp = kv;
	while (kv->k != 0) {
		if (kv->k == k) {
			kv->v = v;
			kv->u = u;
			return true;
		}
		kv++;
	}
	int curln = (kv - tmp);
	dictkv *newkv = (dictkv *)realloc (tmp, (curln + 2) * sizeof (dictkv));
	if (newkv) {
		kv = newkv;
		m->table[bucket] = newkv;
		kv += curln;
		kv->k = k;
		kv->v = v;
		kv->u = u;
		kv++;
		kv->k = 0;
		kv->v = 0;
		kv->u = NULL;
		return true;
	}
	return false;
}

SDB_API ut32 dict_stats(dict *m, ut32 nb) {
	if (((int)nb) < 0) {
		return m->size - 1;
	}
	if (nb < m->size) {
		ut32 j = 0;
		dictkv *kv = (dictkv *)m->table[nb];
		if (kv) {
			while (kv->k != 0) {
				j++;
				kv++;
			}
		}
		return j;
	}
	return 0;
}

SDB_API dictkv *dict_getr(dict *m, dicti k) {
	if (!m->size) {
		return NULL;
	}
	int bucket = dict_bucket (m, k);
	dictkv *kv = (dictkv *)m->table[bucket];
	if (kv) {
		while (kv->k != 0) {
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
	return kv ? kv->v : 0;
}

SDB_API void *dict_getu(dict *m, dicti k) {
	dictkv *kv = dict_getr (m, k);
	return kv ? kv->u : NULL;
}

SDB_API bool dict_add(dict *m, dicti k, dicti v, void *u) {
	return dict_getr (m, k)
		? dict_set (m, k, v, u)
		: false;
}

SDB_API bool dict_del(dict *m, dicti k) {
	int bucket = dict_bucket (m, k);
	if (k == 0) {
		return false;
	}
	dictkv *kv = (dictkv *)m->table[bucket];
	if (kv) {
		while (kv->k != 0) {
			if (kv->k == k) {
				if (m->f) {
					m->f (kv->u);
				}
				dictkv *n = (dictkv *)(kv + 1);
				while (n->k != 0) {
					*kv++ = *n++;
				}
				kv->k = 0;
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
		dictkv *kv = (dictkv *)m->table[i];
		if (kv) {
			while (kv->k) {
				int res = cb (kv, u);
				if (res) {
					iterate = false;
					break;
				}
				kv++;
			}
		}
	}
}
