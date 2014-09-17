/* radare - LGPL - Copyright 2014 - pancake */

#include <r_anal.h>

static int hook_flag_read(RAnalEsil *esil, const char *flag, ut64 *num) {
	sdb_array_add (esil->stats, "flg.read", flag, 0);
	return 0;
}

static int hook_command(RAnalEsil *esil, const char *op) {
	sdb_array_add (esil->stats, "ops.list", op, 0);
	return 0;
}

static int hook_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	sdb_array_add_num (esil->stats, "mem.read", addr, 0);
	return 0;
}

static int hook_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	sdb_array_add_num (esil->stats, "mem.write", addr, 0);
	return 0;
}

static int hook_reg_read(RAnalEsil *esil, const char *name, ut64 *res) {
	if (*name>='0' && *name<='9')
		sdb_array_add (esil->stats, "num.load", name, 0);
	else sdb_array_add (esil->stats, "reg.read", name, 0);
	return 0;
}

static int hook_reg_write(RAnalEsil *esil, const char *name, ut64 val) {
	sdb_array_add (esil->stats, "reg.write", name, 0);
	return 0;
}

static int hook_NOP_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	eprintf ("NOP WRITE AT 0x%08"PFMT64x"\n", addr);
	return 1; // override
}

R_API void r_anal_esil_mem_ro(RAnalEsil *esil, int mem_readonly) {
	if (mem_readonly) {
		esil->hook_mem_write = hook_NOP_mem_write;
	} else {
		esil->hook_mem_write = NULL;
	}
}

R_API void r_anal_esil_stats(RAnalEsil *esil, int enable) {
	if (enable) {
		if (esil->stats) 
			sdb_reset (esil->stats);
		else esil->stats = sdb_new0();
		// reset sdb->stats
		esil->hook_reg_read = hook_reg_read;
		esil->hook_mem_read = hook_mem_read;
		esil->hook_mem_write = hook_mem_write;
		esil->hook_reg_write = hook_reg_write;
		esil->hook_flag_read = hook_flag_read;
		esil->hook_command = hook_command;
	} else {
		esil->hook_mem_write = NULL;
		esil->hook_flag_read = NULL;
		esil->hook_command = NULL;
		sdb_free (esil->stats);
		esil->stats = NULL;
	}
}
