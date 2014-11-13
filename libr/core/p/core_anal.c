/* radare - Copyright 2014 pancake */

#include <r_types.h>
#include <r_core.h>

#define MAXFCNSIZE 4096

static ut64 sdb_array_get_closer_num (Sdb *db, const char *key, ut64 addr) {
	const char *s = sdb_const_get (db, key, NULL);
	const char *next = NULL;
	const char *ptr = NULL;
	ut64 num, closer = UT64_MAX;
	if (!s) return UT64_MAX;
	ptr = s;
	do {
		const char *str = sdb_const_anext (ptr, &next);
		num = sdb_atoi (str);
		if (addr == num)
			return closer;
		if (addr<num)
			continue;
		if (closer > (addr - num))
			closer = num;
		ptr = next;
	} while (next);
	return closer;
}
#define Fbb(x) sdb_fmt(0,"bb.%"PFMT64x,x)
#define FbbTo(x) sdb_fmt(0,"bb.%"PFMT64x".to",x)

static int bbAdd (Sdb *db, ut64 from, ut64 to, ut64 jump, ut64 fail) {
	ut64 last, addr = sdb_array_get_closer_num (db, "bbs", from);
	int add = 1;
	if (addr == UT64_MAX) {
		// add = 1;
	} else if (addr == from) {
		// check if size is the same,
		eprintf ("basic block already analyzed\n");
		add = 0;
	} else {
		last = sdb_num_get (db, Fbb(addr), NULL);
		if (last) {
			if (from >= addr && from < last) {
				eprintf ("OVERLAPS MUST SPLIT\n");
				add = 0;
			}
		}
	}
	if (add) {
eprintf ("ADD NEW BB %llx\n", from);
		sdb_array_add_num (db, "bbs", from, 0);
		sdb_num_set (db, Fbb(from), to, 0);
		if (jump != UT64_MAX)
			sdb_array_set_num (db, FbbTo(from), 0, jump, 0);
		if (fail != UT64_MAX)
			sdb_array_set_num (db, FbbTo(from), 1, fail, 0);
	}
	return 0;
}

int analyzeIterative (RCore *core, Sdb *db, ut64 addr) {
#define addCall(x) sdb_array_add_num (db, "calls", x, 0);
#define addUcall(x) sdb_array_add_num (db, "ucalls", x, 0);
#define addUjmp(x) sdb_array_add_num (db, "ujmps", x, 0);
#define addCjmp(x) sdb_array_add_num (db, "cjmps", x, 0);
#define addRet(x) sdb_array_add_num (db, "rets", x, 0);
#define bbAddOpcode(x) sdb_array_insert_num (db, sdb_fmt (0, "bb.%"PFMT64x, bb_begin), -1, x, 0);
	/* this loop creates basic blocks */
	ut64 oaddr = addr;
	RAnalOp *op;
	int cur = 0;
	int fcn_size = 0;
	ut64 bb_end = addr;
	ut64 bb_begin = addr;

	eprintf ("-> 0x%08"PFMT64x"\n", addr);

	for (;;) {
		op = r_core_anal_op (core, addr + cur);
		if (!op) {
			eprintf ("Cannot analyze opcode at %d\n", addr+cur);
			return R_FALSE;
		}
		eprintf ("0x%08"PFMT64x"  %s\n", addr + cur, op->mnemonic);

		bb_end += op->size;
		fcn_size += op->size;
		bbAddOpcode (addr+cur);

		switch (op->type) {
		case R_ANAL_OP_TYPE_NOP:
			/* If placed at the begining..just skip them */
			if (cur == 0) {
				eprintf ("NOPSKIP %d\n", op->size);
				oaddr += op->size;
				bb_begin = addr = oaddr;
				fcn_size -= op->size;
				cur -= op->size;
			}
			break;
		case R_ANAL_OP_TYPE_CALL:
			/* A call instruction implies that the destination
			 * is a new function unless the address is inside
			 * the same range than the current function */
			addCall (op->jump);
			// add call reference
			break;
		case R_ANAL_OP_TYPE_UCALL:
			/* unknown calls depend on ESIL or DEBUG tracing
			 * information to know the destination, we can mark
			 * those 'calls' for later adding tracepoints in
			 * there to record all possible destinations */
			addUcall (addr+cur);
			break;
		case R_ANAL_OP_TYPE_UJMP:
			/* an unknown jump use to go into computed destinations
			 * outside the current function, but it may result
			 * on an antidisasm trick */ 
			addUjmp (addr+cur);
			/* An unknown jump breaks the basic blocks */
			goto endOfFunction;
		case R_ANAL_OP_TYPE_TRAP:
			addRet (addr + cur);
			goto endOfFunction;
		case R_ANAL_OP_TYPE_RET:
			addRet (addr + cur);
			goto endOfFunction;
		case R_ANAL_OP_TYPE_CJMP:
			/* jumps use to go into the same function, so we*/
			addCjmp (op->jump);
			bbAdd (db, bb_begin, bb_end, op->jump, bb_end);
			bb_begin = bb_end;
			break;
		case R_ANAL_OP_TYPE_JMP:
			/* jumps usually go to the same function, but they
			 * can be used */
			goto endOfFunction;
		case R_ANAL_OP_TYPE_UNK:
			eprintf ("Unknown instruction at 0x%08"PFMT64x"\n", addr+cur);
			goto endOfFunction;
		case R_ANAL_OP_TYPE_ILL:
			eprintf ("HLT\n");
			goto endOfFunction;
		}
		cur += op->size;
		r_anal_op_free (op);
		op = NULL;
	}
	endOfFunction:
	r_anal_op_free (op);
	bbAdd (db, bb_begin, bb_end, UT64_MAX, UT64_MAX);
	return oaddr;
}

static int analyzeFunction (RCore *core, ut64 addr) {
	Sdb *db = sdb_new0 ();
	if (!db) {
		eprintf ("Cannot create db\n");
		return R_FALSE;
	}

	addr = analyzeIterative (core, db, addr);
	if (addr == UT64_MAX) {
		eprintf ("Initial analysis failed\n");
		return R_FALSE;
	}
	sdb_num_set (db, "addr", addr, 0);

	/* those loops can split basic blocks */
	/* iterate over all conditional jumps */
	{
		char *c, *cjmps = sdb_get (db, "cjmps", NULL);
		sdb_aforeach (c, cjmps) {
			ut64 addr = sdb_atoi (c);
			analyzeIterative (core, db, addr);
			sdb_aforeach_next (c);
		}
		free (cjmps);
	}
	{
		char *c, *cjmps = sdb_get (db, "calls", NULL);
		sdb_aforeach (c, cjmps) {
			ut64 addr = sdb_atoi (c);
			// check if call destination is inside the function boundaries
			eprintf ("CALL 0x%08"PFMT64x"\n", addr);
			sdb_aforeach_next (c);
		}
		free (cjmps);
	}
	{
		char *c, *cjmps = sdb_get (db, "jmps", NULL);
		sdb_aforeach (c, cjmps) {
			ut64 addr = sdb_atoi (c);
			// check if call destination is inside the function boundaries
			eprintf ("JMP 0x%08"PFMT64x"\n", addr);
			sdb_aforeach_next (c);
		}
		free (cjmps);
	}
	// Parse SDB and dump results of the analysis
	eprintf ("addr: %s\n", sdb_const_get (db, "addr", NULL));
	eprintf ("calls: %s\n", sdb_const_get (db, "calls", NULL));
	eprintf ("ucalls: %s\n", sdb_const_get (db, "ucalls", NULL));
	eprintf ("cjmps: %s\n", sdb_const_get (db, "cjmps", NULL));
	eprintf ("ujmps: %s\n", sdb_const_get (db, "ujmps", NULL));
	eprintf ("rets: %s\n", sdb_const_get (db, "rets", NULL));
	eprintf ("bbs: %s\n", sdb_const_get (db, "bbs", NULL));
	{
		ut64 min, max;
		char *c, *bbs = sdb_get (db, "bbs", NULL);
		int first = 1;
		sdb_aforeach (c, bbs) {
			ut64 addr = sdb_atoi (c);
			ut64 addr_end = sdb_num_get (db, sdb_fmt(0, "bb.%"PFMT64x, addr), NULL);
			if (first) {
				min = addr;
				max = addr_end;
				first = 0;
			} else {
				if (addr<min)
					min = addr;
				if (addr_end>max)
					max = addr_end;
			}
			// check if call destination is inside the function boundaries
			eprintf ("BB 0x%08"PFMT64x" - 0x%08"PFMT64x"  %d\n",
				addr, addr_end, addr_end-addr);
			eprintf ("  -> %s\n", sdb_const_get (db, FbbTo (addr), 0));
			sdb_aforeach_next (c);
		}
		free (bbs);
		sdb_num_set (db, "size", max-min, 0);
	}
	r_cons_printf ("af+ 0x%08"PFMT64x" %d fcn2.0x%08"PFMT64x,
			sdb_num_get (db, "addr", NULL),
			sdb_num_get (db, "size", NULL),
			sdb_num_get (db, "addr", NULL)
		      );
	eprintf ("size: %s\n", sdb_const_get (db, "size", NULL));
	sdb_free (db);
	return R_TRUE;
}

static int r_cmd_anal_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, "a2", 2)) {
		switch (input[2]) {
		case 'f':
			if (!analyzeFunction (core, core->offset)) {
				eprintf ("a2f: Failed to analyze function.\n");
			}
			break;
		default:
			eprintf ("Usage: a2f\n");
			break;
		}
		return R_TRUE;
	}
	return R_FALSE;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_anal = {
	.name = "anal",
	.desc = "The reworked analysis from scratch thing",
	.license = "LGPL3",
	.call = r_cmd_anal_call,
	.deinit = NULL,
	.init = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_anal
};
#endif
