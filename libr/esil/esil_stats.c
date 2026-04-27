/* radare - LGPL - Copyright 2014-2024 - pancake, condret */

#include <r_esil.h>

static void stats_voyeur_op (void *user, const char *op) {
	sdb_array_add ((Sdb *)user, "ops.list", op, 0);
}

R_API void r_esil_stats(REsil *esil, REsilStats *stats, bool enable) {
	R_RETURN_IF_FAIL (esil && stats);
	if (!enable) {
		if (stats->db) {
			r_esil_del_voyeur (esil, stats->vid[R_ESIL_VOYEUR_OP]);
			sdb_free (stats->db);
			stats->db = NULL;
		}
		return;
	}
	if (stats->db) {
		sdb_reset (stats->db);
		return;
	}
	stats->db = sdb_new0 ();
	if (!stats->db) {
		return;
	}
	stats->vid[R_ESIL_VOYEUR_OP] = r_esil_add_voyeur (esil, stats->db,
		stats_voyeur_op, R_ESIL_VOYEUR_OP);
}

static bool hook_NOP_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	eprintf ("NOP WRITE AT 0x%08"PFMT64x"\n", addr);
	return true;
}

R_API void r_esil_mem_ro(REsil *esil, bool mem_readonly) {
	if (mem_readonly) {
		esil->cb.hook_mem_write = hook_NOP_mem_write;
	} else {
		esil->cb.hook_mem_write = NULL;
	}
}
