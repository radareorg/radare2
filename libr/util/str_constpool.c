/* radare - LGPL - Copyright 2019 thestr4ng3r */

#include "r_util/r_str_constpool.h"

static void kv_fini(HtPPKv *kv) {
	free (kv->key);
}

R_API bool r_str_constpool_init(RStrConstPool *pool) {
	pool->ht = ht_pp_new (NULL, kv_fini, NULL);
	return pool->ht != NULL;
}

R_API void r_str_constpool_fini(RStrConstPool *pool) {
	ht_pp_free (pool->ht);
}

R_API const char *r_str_constpool_get(RStrConstPool *pool, const char *str) {
	if (!str) {
		return NULL;
	}
	HtPPKv *kv = ht_pp_find_kv (pool->ht, str, NULL);
	if (kv) {
		return kv->key;
	}
	ht_pp_insert (pool->ht, str, NULL);
	kv = ht_pp_find_kv (pool->ht, str, NULL);
	if (kv) {
		return kv->key;
	}
	return NULL;
}
