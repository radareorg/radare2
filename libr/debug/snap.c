/* radare - LGPL - Copyright 2015-2024 - pancake, rkx1209 */

#include <r_debug.h>

R_API void r_debug_snap_free(RDebugSnap *snap) {
	if (snap) {
		free (snap->name);
		free (snap->data);
		free (snap);
	}
}

R_API void r_debug_state_reg_spec_free(RDebugStateRegSpec *spec) {
	if (spec) {
		free (spec->name);
		free (spec);
	}
}

R_API void r_debug_state_mem_spec_free(RDebugStateMemSpec *spec) {
	if (spec) {
		free (spec->label);
		free (spec);
	}
}

R_API void r_debug_state_request_free(RDebugStateRequest *request) {
	if (request) {
		r_list_free (request->registers);
		r_list_free (request->memory);
		free (request);
	}
}

R_API void r_debug_state_reg_value_free(RDebugStateRegValue *value) {
	if (value) {
		free (value->name);
		free (value);
	}
}

R_API void r_debug_state_mem_value_free(RDebugStateMemValue *value) {
	if (value) {
		free (value->label);
		free (value->bytes);
		free (value);
	}
}

R_API void r_debug_state_snapshot_free(RDebugStateSnapshot *snapshot) {
	if (snapshot) {
		r_list_free (snapshot->registers);
		r_list_free (snapshot->memory);
		free (snapshot);
	}
}

R_API RDebugStateSnapshot *r_debug_state_snapshot_collect(RDebug *dbg, const RDebugStateRequest *request) {
	R_RETURN_VAL_IF_FAIL (dbg && request, NULL);
	RDebugStateSnapshot *snapshot = R_NEW0 (RDebugStateSnapshot);
	if (!snapshot) {
		return NULL;
	}
	snapshot->registers = r_list_newf ((RListFree)r_debug_state_reg_value_free);
	snapshot->memory = r_list_newf ((RListFree)r_debug_state_mem_value_free);
	if (!snapshot->registers || !snapshot->memory) {
		r_debug_state_snapshot_free (snapshot);
		return NULL;
	}
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, false);
	snapshot->pc = r_debug_reg_get (dbg, "PC");

	RListIter *iter;
	RDebugStateRegSpec *reg_spec;
	r_list_foreach (request->registers, iter, reg_spec) {
		if (!reg_spec || R_STR_ISEMPTY (reg_spec->name)) {
			continue;
		}
		RDebugStateRegValue *value = R_NEW0 (RDebugStateRegValue);
		if (!value) {
			r_debug_state_snapshot_free (snapshot);
			return NULL;
		}
		value->name = strdup (reg_spec->name);
		if (!value->name) {
			r_debug_state_reg_value_free (value);
			r_debug_state_snapshot_free (snapshot);
			return NULL;
		}
		bool err = false;
		value->value = r_debug_reg_get_err (dbg, reg_spec->name, &err, NULL);
		value->found = !err;
		r_list_append (snapshot->registers, value);
	}

	RDebugStateMemSpec *mem_spec;
	r_list_foreach (request->memory, iter, mem_spec) {
		if (!mem_spec || !mem_spec->size) {
			continue;
		}
		RDebugStateMemValue *value = R_NEW0 (RDebugStateMemValue);
		if (!value) {
			r_debug_state_snapshot_free (snapshot);
			return NULL;
		}
		value->addr = mem_spec->addr;
		value->size = mem_spec->size;
		value->label = R_STR_ISNOTEMPTY (mem_spec->label)? strdup (mem_spec->label): NULL;
		value->bytes = malloc (mem_spec->size);
		if ((R_STR_ISNOTEMPTY (mem_spec->label) && !value->label) || !value->bytes) {
			r_debug_state_mem_value_free (value);
			r_debug_state_snapshot_free (snapshot);
			return NULL;
		}
		value->ok = dbg->iob.read_at && dbg->iob.read_at (dbg->iob.io, mem_spec->addr, value->bytes, mem_spec->size);
		r_list_append (snapshot->memory, value);
	}
	return snapshot;
}

R_API char *r_debug_state_snapshot_to_json(const RDebugStateSnapshot *snapshot) {
	R_RETURN_VAL_IF_FAIL (snapshot, NULL);
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	pj_o (pj);
	pj_kn (pj, "pc", snapshot->pc);
	pj_k (pj, "registers");
	pj_a (pj);
	RListIter *iter;
	RDebugStateRegValue *reg;
	r_list_foreach (snapshot->registers, iter, reg) {
		if (!reg) {
			continue;
		}
		pj_o (pj);
		pj_ks (pj, "name", reg->name);
		pj_kn (pj, "value", reg->value);
		pj_kb (pj, "found", reg->found);
		pj_end (pj);
	}
	pj_end (pj);
	pj_k (pj, "memory");
	pj_a (pj);
	RDebugStateMemValue *mem;
	r_list_foreach (snapshot->memory, iter, mem) {
		if (!mem) {
			continue;
		}
		pj_o (pj);
		pj_kn (pj, "addr", mem->addr);
		pj_kn (pj, "size", mem->size);
		if (mem->label) {
			pj_ks (pj, "label", mem->label);
		}
		pj_kb (pj, "ok", mem->ok);
		if (mem->ok && mem->bytes) {
			char *hex = r_hex_bin2strdup (mem->bytes, mem->size);
			if (hex) {
				pj_ks (pj, "bytes", hex);
				free (hex);
			}
		}
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

R_API RDebugSnap *r_debug_snap_map(RDebug *dbg, RDebugMap *map) {
	R_RETURN_VAL_IF_FAIL (dbg && map, NULL);
	if (map->size < 1) {
		R_LOG_ERROR ("Invalid map size");
		return NULL;
	}
	// TODO: Support streaming memory snapshots to avoid big allocations
	if (map->size > dbg->options.maxsnapsize) {
		char *us = r_num_units (NULL, 0, map->size);
		const char *name = r_str_get (map->name);
		R_LOG_ERROR ("Not snapping map %s (%s > dbg.maxsnapsize)", name, us);
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
	R_LOG_INFO ("Reading %d byte(s) from 0x%08"PFMT64x, snap->size, snap->addr);
	dbg->iob.read_at (dbg->iob.io, snap->addr, snap->data, snap->size);

	r_list_append (dbg->snaps, snap);
	return snap;
}

R_API bool r_debug_snap_contains(RDebugSnap *snap, ut64 addr) {
	return (snap->addr <= addr && addr < snap->addr_end);
}

R_API ut8 *r_debug_snap_get_hash(RDebug *dbg, RDebugSnap *snap, int *size) {
	R_RETURN_VAL_IF_FAIL (dbg && snap, NULL);
	if (!dbg->mb.hash) {
		return NULL;
	}
	int outlen = 0;
	ut8 *digest = dbg->mb.hash (&dbg->mb, "sha256", snap->data, snap->size, &outlen);
	if (size) {
		*size = outlen;
	}
	return digest;
}

R_API bool r_debug_snap_is_equal(RDebug *dbg, RDebugSnap *a, RDebugSnap *b) {
	R_RETURN_VAL_IF_FAIL (dbg && a && b, false);
	if (!dbg->mb.hash) {
		return false;
	}
	int alen = 0, blen = 0;
	ut8 *ha = dbg->mb.hash (&dbg->mb, "sha256", a->data, a->size, &alen);
	ut8 *hb = dbg->mb.hash (&dbg->mb, "sha256", b->data, b->size, &blen);
	bool ret = false;
	if (ha && hb && alen == blen) {
		ret = memcmp (ha, hb, alen) == 0;
	}
	free (ha);
	free (hb);
	return ret;
}

R_API int r_debug_snap_delete(RDebug *dbg, int idx) {
	ut32 count = 0;
	RListIter *iter;
	RDebugSnap *snap R_UNUSED;
	if (idx == -1) {
		r_list_free (dbg->snaps);
		dbg->snaps = r_list_newf ((RListFree)r_debug_snap_free);
		return 1;
	}
	r_list_foreach (dbg->snaps, iter, snap) {
		if (idx != -1) {
			if (idx != count) {
				continue;
			}
		}
		R_LOG_DEBUG ("snap %p", snap);
		r_list_delete (dbg->snaps, iter);
		count++;
		break;
	}
	return 1;
}

R_API void r_debug_snap_list(RDebug *dbg, int idx, int mode) {
	const char *comment, *comma;
	ut32 count = 0;
	RListIter *iter;
	RDebugSnap *snap;
	if (mode == 'j')
		dbg->cb_printf ("[");
	r_list_foreach (dbg->snaps, iter, snap) {
		comment = "";
		comma = (iter->n)? ",":"";
		if (idx != -1) {
			if (idx != count) {
				continue;
			}
		}
		if (snap->comment && *snap->comment)
			comment = snap->comment;
		switch (mode) {
		case 'j':
			dbg->cb_printf ("{\"count\":%d,\"addr\":%"PFMT64d",\"size\":%d,\"crc\":%d,\"comment\":\"%s\"}%s",
				count, snap->addr, snap->size, snap->crc, comment, comma);
			break;
		case '*':
			dbg->cb_printf ("dms 0x%08"PFMT64x"\n", snap->addr);
			break;
		default:
			dbg->cb_printf ("%d 0x%08"PFMT64x" - 0x%08"PFMT64x" size: %d crc: %x  --  %s\n",
				count, snap->addr, snap->addr_end, snap->size, snap->crc, comment);
		}
		count++;
	}
	if (mode == 'j') {
		dbg->cb_printf ("]\n");
	}
}

R_API int r_debug_snap_all(RDebug *dbg, int perms) {
	RDebugMap *map;
	RListIter *iter;
	r_debug_map_sync (dbg);
	r_list_foreach (dbg->maps, iter, map) {
		if (!perms || (map->perm & perms)==perms) {
			r_debug_snap_map (dbg, map);
		}
	}
	return 0;
}

R_API int r_debug_snap(RDebug *dbg, ut64 addr) {
	RDebugMap *map = r_debug_map_get (dbg, addr);
	if (!map) {
		R_LOG_ERROR ("Cannot find map at 0x%08"PFMT64x, addr);
		return 0;
	}
	return r_debug_snap_map (dbg, map) != NULL;
}

R_API int r_debug_snap_comment(RDebug *dbg, int idx, const char *msg) {
	RDebugSnap *snap;
	RListIter *iter;
	ut32 count = 0;
	if (!dbg || idx<0 || !msg || !*msg)
		return 0;
	r_list_foreach (dbg->snaps, iter, snap) {
		if (count == idx) {
			free (snap->comment);
			snap->comment = r_str_trim_dup (msg);
			break;
		}
		count++;
	}
	return 1;
}
