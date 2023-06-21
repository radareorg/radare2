/* radare - LGPL - Copyright 2014-2023 - pancake, condret */

#include <r_anal.h>
#include <r_esil.h>

static bool hook_flag_read(REsil *esil, const char *flag, ut64 *num) {
	sdb_array_add (esil->stats, "flg.read", flag, 0);
	return false;
}

static bool hook_command(REsil *esil, const char *op) {
	sdb_array_add (esil->stats, "ops.list", op, 0);
	return false;
}

static bool hook_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	sdb_array_add_num (esil->stats, "mem.read", addr, 0);
	return false;
}

static void obs_mem_read(void *user, ut64 addr, ut8 *buf, int len) {
	hook_mem_read ((REsil *)user, addr, buf, len);
}

static bool hook_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	sdb_array_add_num (esil->stats, "mem.write", addr, 0);
	return false;
}

static void obs_mem_write(void *user, ut64 addr, ut8 *buf, int len) {
	hook_mem_write ((REsil *)user, addr, buf, len);
}

static bool hook_reg_read(REsil *esil, const char *name, ut64 *res, int *size) {
	const char *key = (*name>='0' && *name<='9')? "num.load": "reg.read";
	sdb_array_add (esil->stats, key, name, 0);
	return false;
}

static void obs_reg_read(void *user, const char *name) {
	ut64 fake_val;
	int fake_size;
	hook_reg_read ((REsil *)user, name, &fake_val, &fake_size);
}

static bool hook_reg_write(REsil *esil, const char *name, ut64 *val) {
	sdb_array_add (esil->stats, "reg.write", name, 0);
	return false;
}

static void obs_reg_write(void *user, const char *name, ut64 val) {
	hook_reg_write ((REsil *)user, name, &val);
}

static bool hook_NOP_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	eprintf ("NOP WRITE AT 0x%08"PFMT64x"\n", addr);
	return true;
}

R_API void r_esil_mem_ro(REsil *esil, int mem_readonly) {
	if (mem_readonly) {
		esil->cb.hook_mem_write = hook_NOP_mem_write;
	} else {
		esil->cb.hook_mem_write = NULL;
	}
}

R_API void r_esil_stats(REsil *esil, int enable) {
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
		if (esil->stats_mr_handle != UT32_MAX) {
			esil->stats_mr_handle = r_esil_add_mem_read_obs (esil, obs_mem_read, esil);
		}
		if (esil->stats_mw_handle != UT32_MAX) {
			esil->stats_mw_handle = r_esil_add_mem_write_obs (esil, obs_mem_write, esil);
		}
		if (esil->stats_rr_handle != UT32_MAX) {
			esil->stats_rr_handle = r_esil_add_reg_read_obs (esil, obs_reg_read, esil);
		}
		if (esil->stats_rw_handle != UT32_MAX) {
			esil->stats_rw_handle = r_esil_add_reg_write_obs (esil, obs_reg_write, esil);
		}
		esil->cb.hook_flag_read = hook_flag_read;
		esil->cb.hook_flag_read = hook_flag_read;
		esil->cb.hook_command = hook_command;
	} else {
		r_esil_del_mem_read_obs (esil, esil->stats_mr_handle);
		esil->stats_mr_handle = UT32_MAX;
		r_esil_del_mem_write_obs (esil, esil->stats_mw_handle);
		esil->stats_mw_handle = UT32_MAX;
		r_esil_del_reg_read_obs (esil, esil->stats_rr_handle);
		esil->stats_rr_handle = UT32_MAX;
		r_esil_del_reg_write_obs (esil, esil->stats_rw_handle);
		esil->stats_rw_handle = UT32_MAX;
		esil->cb.hook_mem_write = NULL;
		esil->cb.hook_flag_read = NULL;
		esil->cb.hook_command = NULL;
		sdb_free (esil->stats);
		esil->stats = NULL;
	}
}
