/* radare - LGPL - Copyright 2014-2024 - pancake, condret */

#include <r_esil.h>

#if USE_NEW_ESIL
static void stats_voyeur_reg_read (void *user, const char *name, ut64 val) {
	const char *key = (*name>='0' && *name<='9')? "num.load": "reg.read";
	sdb_array_add ((Sdb *)user, key, name, 0);
}

static void stats_voyeur_reg_write (void *user, const char *name, ut64 old, ut64 val) {
	sdb_array_add ((Sdb *)user, "reg.write", name, 0);
}

static void stats_voyeur_mem_read (void *user, ut64 addr, const ut8 *buf, int len) {
	sdb_array_add_num ((Sdb *)user, "mem.read", addr, 0);
}

static void stats_voyeur_mem_write (void *user, ut64 addr, const ut8 *old, const ut8 *buf, int len) {
	sdb_array_add_num ((Sdb *)user, "mem.write", addr, 0);
}

static void stats_voyeur_op (void *user, const char *op) {
	sdb_array_add ((Sdb *)user, "ops.list", op, 0);
}
#endif

#if ESIL_UNUSED
static void esil_stats_old(REsil *esil, bool enable) {
	if (enable) {
		if (esil->stats) {
			sdb_reset (esil->stats);
		} else {
			esil->stats = sdb_new0 ();
		}
		// reset sdb->stats
		esil->cb.hook_reg_read = hook_reg_read;
		esil->cb.hook_mem_read = hook_mem_read;
		esil->cb.hook_mem_write = hook_mem_write;
		esil->cb.hook_reg_write = hook_reg_write;
		esil->cb.hook_command = hook_command;
	} else {
		esil->cb.hook_mem_write = NULL;
		esil->cb.hook_command = NULL;
		sdb_free (esil->stats);
		esil->stats = NULL;
	}
}
#endif

R_API void r_esil_stats(REsil *esil, REsilStats *stats, bool enable) {
#if USE_NEW_ESIL
	R_RETURN_IF_FAIL (esil && stats);
	if (!enable) {
		if (stats->db) {
			r_esil_del_voyeur (esil, stats->vid[R_ESIL_VOYEUR_REG_READ]);
			r_esil_del_voyeur (esil, stats->vid[R_ESIL_VOYEUR_REG_WRITE]);
			r_esil_del_voyeur (esil, stats->vid[R_ESIL_VOYEUR_MEM_READ]);
			r_esil_del_voyeur (esil, stats->vid[R_ESIL_VOYEUR_MEM_WRITE]);
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
	stats->vid[R_ESIL_VOYEUR_REG_READ] = r_esil_add_voyeur (esil, stats->db,
		stats_voyeur_reg_read, R_ESIL_VOYEUR_REG_READ);
	stats->vid[R_ESIL_VOYEUR_REG_WRITE] = r_esil_add_voyeur (esil, stats->db,
		stats_voyeur_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	stats->vid[R_ESIL_VOYEUR_MEM_READ] = r_esil_add_voyeur (esil, stats->db,
		stats_voyeur_mem_read, R_ESIL_VOYEUR_MEM_READ);
	stats->vid[R_ESIL_VOYEUR_MEM_WRITE] = r_esil_add_voyeur (esil, stats->db,
		stats_voyeur_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	stats->vid[R_ESIL_VOYEUR_OP] = r_esil_add_voyeur (esil, stats->db,
		stats_voyeur_op, R_ESIL_VOYEUR_OP);
#else
	esil_stats_old (esil, enable);
#endif
}

#if 0
static bool hook_command(REsil *esil, const char *op) {
	sdb_array_add (esil->stats, "ops.list", op, 0);
	return false;
}

static bool hook_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	sdb_array_add_num (esil->stats, "mem.read", addr, 0);
	return false;
}

static bool hook_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	sdb_array_add_num (esil->stats, "mem.write", addr, 0);
	return false;
}

static bool hook_reg_read(REsil *esil, const char *name, ut64 *res, int *size) {
	const char *key = (*name>='0' && *name<='9')? "num.load": "reg.read";
	sdb_array_add (esil->stats, key, name, 0);
	return false;
}

static bool hook_reg_write(REsil *esil, const char *name, ut64 *val) {
	sdb_array_add (esil->stats, "reg.write", name, 0);
	return false;
}
#endif

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

