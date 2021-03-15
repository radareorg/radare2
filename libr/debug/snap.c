/* radare - LGPL - Copyright 2015-2021 - pancake, rkx1209 */

#include <r_debug.h>
#include <r_hash.h>

R_API void r_debug_snap_free(RDebugSnap *snap) {
	if (snap) {
		free (snap->name);
		free (snap->data);
		R_FREE (snap);
	}
}

R_API RDebugSnap *r_debug_snap_map(RDebug *dbg, RDebugMap *map) {
	r_return_val_if_fail (dbg && map, NULL);
	if (map->size < 1) {
		eprintf ("Invalid map size\n");
		return NULL;
	}
	// TODO: Support streaming memory snapshots to avoid big allocations
	if (map->size > dbg->maxsnapsize) {
		char *us = r_num_units (NULL, 0, map->size);
		const char *name = r_str_get (map->name);
		eprintf ("Not snapping map %s (%s > dbg.maxsnapsize)\n", name, us);
		free (us);
		return NULL;
	}

	RDebugSnap *snap = R_NEW0 (RDebugSnap);
	if (!snap) {
		return NULL;
	}

	snap->name = strdup (map->name);
	snap->addr = map->addr;
	snap->addr_end = map->addr_end;
	snap->size = map->size;
	snap->perm = map->perm;
	snap->user = map->user;
	snap->shared = map->shared;

	snap->data = malloc (map->size);
	if (!snap->data) {
		r_debug_snap_free (snap);
		return NULL;
	}
	eprintf ("Reading %d byte(s) from 0x%08"PFMT64x "...\n", snap->size, snap->addr);
	dbg->iob.read_at (dbg->iob.io, snap->addr, snap->data, snap->size);

	return snap;
}

R_API bool r_debug_snap_contains(RDebugSnap *snap, ut64 addr) {
	return (snap->addr <= addr && addr >= snap->addr_end);
}

R_API ut8 *r_debug_snap_get_hash(RDebugSnap *snap) {
	ut64 algobit = r_hash_name_to_bits ("sha256");
	RHash *ctx = r_hash_new (true, algobit);
	if (!ctx) {
		return NULL;
	}

	r_hash_do_begin (ctx, algobit);
	r_hash_calculate (ctx, algobit, snap->data, snap->size);
	r_hash_do_end (ctx, algobit);

	ut8 *ret = malloc (R_HASH_SIZE_SHA256);
	if (!ret) {
		r_hash_free (ctx);
		return NULL;
	}
	memcpy (ret, ctx->digest, R_HASH_SIZE_SHA256);

	r_hash_free (ctx);
	return ret;
}

R_API bool r_debug_snap_is_equal(RDebugSnap *a, RDebugSnap *b) {
	bool ret = false;
	ut64 algobit = r_hash_name_to_bits ("sha256");
	RHash *ctx = r_hash_new (true, algobit);
	if (!ctx) {
		return ret;
	}

	r_hash_do_begin (ctx, algobit);
	r_hash_calculate (ctx, algobit, a->data, a->size);
	r_hash_do_end (ctx, algobit);

	ut8 *temp = malloc (R_HASH_SIZE_SHA256);
	if (!temp) {
		r_hash_free (ctx);
		return ret;
	}
	memcpy (temp, ctx->digest, R_HASH_SIZE_SHA256);

	r_hash_do_begin (ctx, algobit);
	r_hash_calculate (ctx, algobit, b->data, b->size);
	r_hash_do_end (ctx, algobit);

	ret = memcmp (temp, ctx->digest, R_HASH_SIZE_SHA256) == 0;
	free (temp);
	r_hash_free (ctx);
	return ret;
}
