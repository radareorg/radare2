/* radare - LGPL - Copyright 2015 - pancake */

#include <r_anal.h>

#define DB esil->db_trace
#define KEY(x) sdb_fmt (0, "%d."x, esil->trace_idx)
#define KEYAT(x,y) sdb_fmt (0, "%d."x".0x%"PFMT64x, esil->trace_idx, y)
#define KEYREG(x,y) sdb_fmt (0, "%d."x".%s", esil->trace_idx, y)

static int ocbs_set = false;
static RAnalEsilCallbacks ocbs = {0};

static int trace_hook_reg_read(RAnalEsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	if (*name=='0') {
		//eprintf ("Register not found in profile\n");
		return 0;
	}
	if (ocbs.hook_reg_read) {
		RAnalEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_reg_read (esil, name, res, size);
		esil->cb = cbs;
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read (esil, name, res, size);
	}
	if (ret) {
		ut64 val = *res;
		//eprintf ("[ESIL] REG READ %s 0x%08"PFMT64x"\n", name, val);
		sdb_array_add (DB, KEY ("reg.read"), name, 0);
		sdb_num_set (DB, KEYREG ("reg.read", name), val, 0);
	} //else {
		//eprintf ("[ESIL] REG READ %s FAILED\n", name);
	//}
	return ret;
}

static int trace_hook_reg_write(RAnalEsil *esil, const char *name, ut64 *val) {
	int ret = 0;
	//eprintf ("[ESIL] REG WRITE %s 0x%08"PFMT64x"\n", name, *val);
	sdb_array_add (DB, KEY ("reg.write"), name, 0);
	sdb_num_set (DB, KEYREG ("reg.write", name), *val, 0);
	if (ocbs.hook_reg_write) {
		RAnalEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_reg_write (esil, name, val);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	char *hexbuf = calloc ((1 + len), 4);
	int ret = 0;
	if (esil->cb.mem_read) {
		ret = esil->cb.mem_read (esil, addr, buf, len);
	}
	sdb_array_add_num (DB, KEY ("mem.read"), addr, 0);
	r_hex_bin2str (buf, len, hexbuf);
	sdb_set (DB, KEYAT ("mem.read.data", addr), hexbuf, 0);
	//eprintf ("[ESIL] MEM READ 0x%08"PFMT64x" %s\n", addr, hexbuf);
	free (hexbuf);

	if (ocbs.hook_mem_read) {
		RAnalEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_mem_read (esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

static int trace_hook_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret = 0;
	char *hexbuf = malloc ((1+len)*3);
	sdb_array_add_num (DB, KEY ("mem.write"), addr, 0);
	r_hex_bin2str (buf, len, hexbuf);
	sdb_set (DB, KEYAT ("mem.write.data", addr), hexbuf, 0);
	//eprintf ("[ESIL] MEM WRITE 0x%08"PFMT64x" %s\n", addr, hexbuf);
	free (hexbuf);

	if (ocbs.hook_mem_write) {
		RAnalEsilCallbacks cbs = esil->cb;
		esil->cb = ocbs;
		ret = ocbs.hook_mem_write (esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

R_API void r_anal_esil_trace (RAnalEsil *esil, RAnalOp *op) {
	const char *expr = r_strbuf_get (&op->esil);
	int esil_debug = esil->debug;
	if (ocbs_set) {
		eprintf ("cannot call recursively\n");
	}
	ocbs = esil->cb;
	ocbs_set = true;
	if (!DB) DB = sdb_new0 ();

	sdb_num_set (DB, "idx", esil->trace_idx, 0);
	sdb_num_set (DB, KEY ("addr"), op->addr, 0);
//	sdb_set (DB, KEY ("opcode"), op->mnemonic, 0);
//	sdb_set (DB, KEY ("addr"), expr, 0);

	//eprintf ("[ESIL] ADDR 0x%08"PFMT64x"\n", op->addr);
	//eprintf ("[ESIL] OPCODE %s\n", op->mnemonic);
	//eprintf ("[ESIL] EXPR = %s\n", expr);
	/* set hooks */
	esil->debug = 0;
	esil->cb.hook_reg_read = trace_hook_reg_read;
	esil->cb.hook_reg_write = trace_hook_reg_write;
	esil->cb.hook_mem_read = trace_hook_mem_read;
	esil->cb.hook_mem_write = trace_hook_mem_write;
	/* evaluate esil expression */
	r_anal_esil_parse (esil, expr);
	/* restore hooks */
	esil->cb = ocbs;
	ocbs_set = false;
	esil->debug = esil_debug;
	esil->trace_idx ++;
}

R_API void r_anal_esil_trace_list (RAnalEsil *esil) {
	/* TODO. make output more userfriendly */
	sdb_list (esil->db_trace);
}

R_API void r_anal_esil_trace_show(RAnalEsil *esil, int idx) {
	PrintfCallback p = esil->anal->cb_printf;
	const char *str2;
	const char *str;
	int trace_idx = esil->trace_idx;
	esil->trace_idx = idx;

	str2 = sdb_const_get (DB, KEY ("addr"), 0);
	if (!str2) {
		return;
	}
	p ("dr pc = %s\n", str2);
	/* registers */
	str = sdb_const_get (DB, KEY ("reg.read"), 0);
	if (str) {
		char regname[32];
		const char *next, *ptr = str;
		if (ptr && *ptr) {
			do {
				const char *ztr = sdb_const_anext (ptr, &next);
				int len = next? (int)(size_t)(next-ztr)-1 : strlen (ztr);
				if (len <sizeof(regname)) {
					memcpy (regname, ztr, len);
					regname[len] = 0;
					str2 = sdb_const_get (DB, KEYREG ("reg.read", regname), 0);
					p ("dr %s = %s\n", regname, str2);
				} else {
					eprintf ("Invalid entry in reg.read\n");
				}
				ptr = next;
			} while (next);
		}
	}
	/* memory */
	str = sdb_const_get (DB, KEY ("mem.read"), 0);
	if (str) {
		char addr[64];
		const char *next, *ptr = str;
		if (ptr && *ptr) {
			do {
				const char *ztr = sdb_const_anext (ptr, &next);
				int len = next? (int)(size_t)(next-ztr)-1 : strlen (ztr);
				if (len <sizeof(addr)) {
					memcpy (addr, ztr, len);
					addr[len] = 0;
					str2 = sdb_const_get (DB, KEYAT ("mem.read.data",
						r_num_get (NULL, addr)), 0);
					p ("wx %s @ %s\n", str2, addr);
				} else {
					eprintf ("Invalid entry in reg.read\n");
				}
				ptr = next;
			} while (next);
		}
	}

	esil->trace_idx = trace_idx;
}
