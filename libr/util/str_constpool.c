/* radare - LGPL - Copyright 2019-2022 pancake, thestr4ng3r */

#include "r_util/r_str_constpool.h"
#include "r_util/r_assert.h"

static void kv_fini(HtPPKv *kv) {
	if (kv) {
		free (kv->key);
	}
}

R_API bool r_str_constpool_init(RStrConstPool *pool) {
	r_return_val_if_fail (pool, false);
	pool->ht = ht_pp_new (NULL, kv_fini, NULL);
	return pool->ht;
}

R_API void r_str_constpool_fini(RStrConstPool *pool) {
	if (pool) {
		ht_pp_free (pool->ht);
	}
}

R_API RStrConstPool *r_str_constpool_new(void) {
	RStrConstPool *cp = R_NEW0 (RStrConstPool);
	r_str_constpool_init (cp);
	return cp;
}

R_API void r_str_constpool_free(RStrConstPool *cp) {
	if (cp) {
		r_str_constpool_fini (cp);
		free (cp);
	}
}

R_API const char *r_str_constpool_get(RStrConstPool *pool, const char *str) {
	r_return_val_if_fail (pool && str, NULL);
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
