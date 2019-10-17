/* radare - LGPL - Copyright 2019 thestr4ng3r */

#include "r_util/r_str_constpool.h"

R_API bool r_str_constpool_init(RStrConstPool *pool) {
	pool->ht = sdb_ht_new ();
	return pool->ht != NULL;
}

R_API void r_str_constpool_fini(RStrConstPool *pool) {
	sdb_ht_free (pool->ht);
}

R_API const char *r_str_constpool_get(RStrConstPool *pool, const char *str) {
	if (!str) {
		return NULL;
	}
	sdb_ht_insert (pool->ht, str, str);
	return sdb_ht_find (pool->ht, str, NULL);
}
