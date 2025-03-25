/* radare - Copyright 2014-2024 pancake, defragger */

#define R_LOG_ORIGIN "a2f"

#include <r_types.h>
#include <r_core.h>
#include <r_io.h>

#define MAXFCNSIZE 4096

#define Fbb(x) r_strf("bb.%"PFMT64x,x)
#define Fhandled(x) r_strf("handled.%"PFMT64x,x)
#define FbbTo(x) r_strf("bb.%"PFMT64x".to",x)

static ut64 getCrossingBlock(Sdb *db, const char *key, ut64 start, ut64 end) {
	r_strf_buffer (64);
	ut64 block_start, block_end;
	ut64 nearest_start = UT64_MAX;
	const char *s = sdb_const_get (db, key, NULL);
	const char *next = NULL;
	const char *ptr = NULL;
	if (!s) {
		return UT64_MAX;
	}
	ptr = s;
	do {
		next = sdb_const_anext (ptr);
		block_start = sdb_atoi (ptr);

		if (start == block_start) { // case 5
			return start;
		}

		block_end = sdb_num_get (db, Fbb (block_start), NULL);
		if (block_end) {
			if (start > block_start && start < block_end) { // case 2
				// start is inside the block
				return block_start;
			}
			if (start < block_start && end >= block_end) {
				// crossing the start of the block
				if (nearest_start > block_start) {
					nearest_start = block_start;
				}
			}
		}
		ptr = next;
	} while (next);

	return nearest_start;
}

/*
 bb.<addr-of-basic-block>=<end-address-of-basic-block>
 bb.<addr-of-basic-block>.to=array,of,destination,addresses
*/

static int bbAdd(Sdb *db, ut64 from, ut64 to, ut64 jump, ut64 fail) {
	r_strf_buffer (64);
	ut64 block_start = getCrossingBlock (db, "bbs", from, to);
	bool add = true;
	if (block_start == UT64_MAX) {
		// add = 1;
	} else if (block_start == from) {
		// check if size is the same,
		add = false;
	} else {
		/*
		   from = start address of new basic block
		   to = end address of new basic block
		   jump = destination basic block
		   fail = fallback jump of basic block
		   addr = previous closer basic block start address
		   addr_end = previous closer basic block start address
		 */
		// found a possible block
		if (from > block_start) {
			// from inside
			// RESIZE this
			r_strf_var (bbst, 64, "bb.%"PFMT64x, block_start);
			r_strf_var (bben, 64, "bb.%"PFMT64x".to", block_start);
			sdb_num_set (db, bbst, from, 0);
			sdb_num_set (db, bben, from, 0);
			sdb_array_set_num (db, bben, 0, from, 0);
			sdb_array_set_num (db, bben, 1, UT64_MAX, 0);
		} else {
			// < the current runs into a known block
			to = block_start;
			jump = block_start;
			fail = UT64_MAX;
		}
	}
	if (add) {
		sdb_array_add_num (db, "bbs", from, 0);
		sdb_num_set (db, Fbb (from), to, 0);
		sdb_array_set_num (db, FbbTo (from), 0, jump, 0);
		sdb_array_set_num (db, FbbTo (from), 1, fail, 0);
		sdb_num_min (db, "min", from, 0);
		sdb_num_max (db, "max", to, 0);
	}
	return 0;
}

static void addTarget(RCore *core, RStack *stack, Sdb *db, ut64 addr) {
	r_strf_buffer (64);
	if (sdb_num_get (db, Fhandled (addr), NULL)) {
		// already set
		return;
	}
	ut64* value = (ut64*) calloc (1, sizeof (ut64));
	if (!value) {
		R_LOG_DEBUG ("Failed to allocate memory for address stack");
		return;
	}
	*value = addr;
	if (!r_stack_push (stack, (void*)value)) {
		R_LOG_DEBUG ("Failed to push address on stack");
		free (value);
		return;
	}
	sdb_num_set (db, Fhandled (addr), 1, 0);
}

static ut64 analyzeStackBased(RCore *core, Sdb *db, ut64 addr, RList *delayed_commands) {
#define addCall(x) sdb_array_add_num (db, "calls", x, 0);
#define addUcall(x) sdb_array_add_num (db, "ucalls", x, 0);
#define addUjmp(x) sdb_array_add_num (db, "ujmps", x, 0);
#define addCjmp(x) sdb_array_add_num (db, "cjmps", x, 0);
#define addRet(x) sdb_array_add_num (db, "rets", x, 0);
#define bbAddOpcode(x) sdb_array_insert_num (db, r_strf ("bb.%"PFMT64x, addr+cur), -1, x, 0);
	r_strf_buffer (32);
	ut64 oaddr = addr;
	ut64 *value = NULL;
	RAnalOp *op;
	int cur = 0;
	bool block_end = false;
	RStack *stack = r_stack_newf (10, free);
	addTarget (core, stack, db, addr);
	const ut64 maxfcnsize = 1024 * 32;

	while (!r_stack_is_empty (stack)) {
		block_end = false;
		value = (ut64*) r_stack_pop (stack);
		if (!value) {
			R_LOG_ERROR ("Failed to pop next address from stack");
			break;
		}

		addr = *value;
		free (value);
		cur = 0;
		while (!block_end && cur < maxfcnsize) {
			// op = r_core_anal_op (core, addr + cur, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
			op = R_NEW0 (RAnalOp);
			// op = r_core_anal_op (core, addr + cur, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
			op->addr = addr + cur;
			op->size = 32; // maxopsz
			op->bytes = malloc (op->size); // maxopsz
			RIOBind *iob = &core->anal->iob;
			if (iob->read_at (iob->io, op->addr, op->bytes, op->size) < 1) {
				R_LOG_DEBUG ("Cannot read opcode at 0x%"PFMT64x, addr+cur);
				oaddr = UT64_MAX;
				r_anal_op_free (op);
				op = NULL;
				break;
			}
			// RArchSession *as = core->anal->arch->session;
			// bool res = r_arch_decode (as, op, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
			bool res = r_anal_op (core->anal, op, addr + cur, op->bytes, op->size, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);
			if (!res || !op->mnemonic) {
				R_LOG_DEBUG ("Cannot analyze opcode at 0x%"PFMT64x, addr+cur);
				oaddr = UT64_MAX;
				r_anal_op_free (op);
				op = NULL;
				break;
			}
			if (op->mnemonic[0] == '?') {
				R_LOG_DEBUG ("a:a2f Cannot analyze opcode at 0x%"PFMT64x, addr+cur);
				oaddr = UT64_MAX;
				break;
			}

			bbAddOpcode (addr + cur);
			switch (op->type) {
			case R_ANAL_OP_TYPE_NOP:
				// skip nops
				if (cur == 0) {
					cur -= op->size;
					addr += op->size;
					oaddr += op->size;
				}
				break;
			case R_ANAL_OP_TYPE_CALL:
				/* A call instruction implies that the destination
				 * is a new function unless the address is inside
				 * the same range than the current function */
				addCall (op->jump);
				r_list_append (delayed_commands, r_str_newf ("axC %"PFMT64d" %"PFMT64d, op->jump, addr + cur));
				break;
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_ICALL:
			case R_ANAL_OP_TYPE_RCALL:
			case R_ANAL_OP_TYPE_IRCALL:
			case R_ANAL_OP_TYPE_CCALL:
			case R_ANAL_OP_TYPE_UCCALL:
				/* unknown calls depend on ESIL or DEBUG tracing
				 * information to know the destination, we can mark
				 * those 'calls' for later adding tracepoints in
				 * there to record all possible destinations */
				addUcall (addr + cur);
				if (op->ptr != UT64_MAX) {
					r_list_append (delayed_commands, r_str_newf ("axC %"PFMT64d" %"PFMT64d, op->ptr, addr + cur));
				}
				break;
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_MCJMP:
			case R_ANAL_OP_TYPE_UCJMP:
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_IRJMP:
				/* an unknown jump use to go into computed destinations
				 * outside the current function, but it may result
				 * on an antidisasm trick */
				addUjmp (addr + cur);
				/* An unknown jump breaks the basic blocks */
				block_end = true; // XXX more investigation here
				break;
			case R_ANAL_OP_TYPE_TRAP:
				if (cur == 0) {
					// skip leading int3
					cur -= op->size;
					addr += op->size;
					oaddr += op->size;
				} else {
					block_end = true;
				}
				break;
			case R_ANAL_OP_TYPE_CRET:
			case R_ANAL_OP_TYPE_RET:
				addRet (addr + cur);
				bbAdd (db, addr, addr + cur + op->size, UT64_MAX, UT64_MAX);
				block_end = true;
				break;
			case R_ANAL_OP_TYPE_CJMP:
				addCjmp (addr+cur);
				bbAdd (db, addr, addr + cur + op->size, op->jump, addr + cur + op->size);
				addTarget (core, stack, db, op->jump);
				addTarget (core, stack, db, addr + cur + op->size);
				block_end = true;
				r_list_append (delayed_commands, r_str_newf ("axc %"PFMT64d" %"PFMT64d, op->jump, addr + cur));
				break;
			case R_ANAL_OP_TYPE_JMP:
				addUjmp (addr+cur);
				bbAdd (db, addr, addr + cur + op->size, op->jump, UT64_MAX);
				addTarget (core, stack, db, op->jump);
				block_end = true;
				r_list_append (delayed_commands, r_str_newf ("axc %"PFMT64d" %"PFMT64d, op->jump, addr + cur));
				break;
			case R_ANAL_OP_TYPE_UNK:
			case R_ANAL_OP_TYPE_ILL:
				R_LOG_DEBUG ("a2f: Invalid instruction");
				block_end = true;
				break;
			default:
				if (op->ptr != UT64_MAX) {
					r_list_append (delayed_commands, r_str_newf ("axd %"PFMT64d" %"PFMT64d, op->ptr, addr + cur));
				}
				break;
			}
			cur += op->size;
			r_anal_op_free (op);
			op = NULL;
		}
	}
	if (block_end) {
		bbAdd (db, addr, addr + cur, UT64_MAX, UT64_MAX);
	}
	r_stack_free (stack);
	return oaddr;
}

static ut64 getFunctionSize(Sdb *db) {
	r_strf_buffer (64);
	ut64 min = UT64_MAX, max = 0;
	char *c, *bbs = sdb_get (db, "bbs", NULL);
	bool first = true;
	sdb_aforeach (c, bbs) {
		ut64 addr = sdb_atoi (c);
		ut64 addr_end = sdb_num_get (db, Fbb (addr), NULL);
		if (first) {
			min = addr;
			max = addr_end;
			first = false;
		} else {
			if (addr < min) {
				min = addr;
			}
			if (addr_end > max) {
				max = addr_end;
			}
		}
		sdb_aforeach_next (c);
	}
	free (bbs);
	return max - min;
}

static bool analyzeFunction(RCore *core, ut64 addr) {
	r_strf_buffer (64);
	Sdb *db = sdb_new0 ();
	RFlagItem *fi;
	RListIter *iter;
	ut64 loc_addr = 0;
	RCoreBind coreb = core->anal->coreb;
	char *command = NULL;
	char *function_label;
	// bool vars = r_config_get_b (core->config, "anal.vars");
	bool vars = false; // coreb.cfggeti (coreb.core, "anal.vars"); // getr_config_get_b (core->config, "anal.vars");
	if (!db) {
		R_LOG_ERROR ("Cannot create db");
		return false;
	}

	RList *delayed_commands = r_list_newf (free);
	if (!delayed_commands) {
		sdb_free (db);
		return false;
	}

	ut64 a = analyzeStackBased (core, db, addr, delayed_commands);
	if (addr == UT64_MAX) {
		R_LOG_ERROR ("Initial analysis failed");
		return false;
	}
	if (a != UT64_MAX) {
		addr = a;
	}
	sdb_num_set (db, "addr", addr, 0);

	//TODO add the possible addresses to the analysis stack
	//TODO add xrefs
	//eprintf ("addr: %s\n", sdb_const_get (db, "addr", NULL));
	//eprintf ("calls: %s\n", sdb_const_get (db, "calls", NULL));
	//eprintf ("ucalls: %s\n", sdb_const_get (db, "ucalls", NULL));
	//eprintf ("cjmps: %s\n", sdb_const_get (db, "cjmps", NULL));
	//eprintf ("ujmps: %s\n", sdb_const_get (db, "ujmps", NULL));
	//eprintf ("rets: %s\n", sdb_const_get (db, "rets", NULL));
	//eprintf ("bbs: %s\n", sdb_const_get (db, "bbs", NULL));

	// fcnfit to get fcn size
	sdb_num_set (db, "size", getFunctionSize (db), 0);

	// receiving a possible flag to label the new function
	fi = r_flag_get_at (core->flags, addr, false);
	if (fi && fi->name && strncmp (fi->name, "sect", 4)) {
		function_label = strdup (fi->name);
	} else {
		const char *fcnpfx = coreb.cfgget (coreb.core, "anal.fcnprefix");
		if (R_STR_ISEMPTY (fcnpfx)) {
			function_label = r_str_newf ("fcn_%08"PFMT64x, addr);
		} else {
			function_label = r_str_newf ("%s.%08"PFMT64x, fcnpfx, addr);
		}
	}
	// loc_addr = core->addr; // sdb_num_get (db, "addr", NULL);
	loc_addr = sdb_num_get (db, "addr", NULL);
	RAnalFunction *fcn_at_addr = r_anal_get_function_at (core->anal, loc_addr);
	if (fcn_at_addr) {
		free (function_label);
		return false;
	}

	// r_cons_printf ("af+ 0x%08"PFMT64x" %s\n", loc_addr, function_label);
	coreb.cmdf (coreb.core, "af+ 0x%08"PFMT64x" %s", loc_addr, function_label);
	// r_core_cmdf (core, "af+ 0x%08"PFMT64x" %s", loc_addr, function_label);
	{
		char *c, *bbs = sdb_get (db, "bbs", NULL);
		sdb_aforeach (c, bbs) {
			ut64 addr = sdb_atoi (c);
			ut64 addr_end = sdb_num_get (db, Fbb (addr), NULL);
			// check if call destination is inside the function boundaries
			ut64 jump = sdb_array_get_num (db, FbbTo (addr), 0, NULL);
			ut64 fail = sdb_array_get_num (db, FbbTo (addr), 1, NULL);

			// r_cons_printf ("afb+ 0x%"PFMT64x" 0x%"PFMT64x" %d 0x%"PFMT64x" 0x%"PFMT64x"\n",
			// 	loc_addr, addr, (int)(addr_end - addr), jump, fail);
			coreb.cmdf (coreb.core, "afb+ 0x%"PFMT64x" 0x%"PFMT64x" %d 0x%"PFMT64x" 0x%"PFMT64x,
			  	loc_addr, addr, (int)(addr_end - addr), jump, fail);
			sdb_aforeach_next (c);
		}
		if (vars) {
			// handling arguments
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
			if (fcn && !r_list_empty (fcn->bbs)) {
				coreb.cmdf (coreb.core, "afva @ 0x%"PFMT64x, addr);
				// r_core_cmdf (core, "afva @ 0x%"PFMT64x, addr);
			}
		}
		free (bbs);
		free (function_label);
	}
	r_list_foreach (delayed_commands, iter, command) {
		if (command) {
			coreb.cmd (coreb.core, command);
			// r_core_cmd0 (core, command);
			command = NULL;
		}
	}
	// TODO
	// xrefs are added but are not mentioned in afi
	// analyze next calls
	//	{
	//		char *c, *calls = sdb_get (db, "calls", NULL);
	//		sdb_aforeach (c, calls) {
	//			ut64 addr = sdb_atoi (c);
	//			r_cons_printf ("a2f @ 0x%"PFMT64x"\n", addr);
	//			sdb_aforeach_next (c);
	//		}
	//		free (calls);
	//	}
	r_list_free (delayed_commands);
	sdb_free (db);
	return true;
}

// static int r_cmd_anal_call(void *user, const char *input) {
static bool analcall(RAnal *anal, const char *input) {
	RCore *core = (RCore *) anal->coreb.core;
	if (!r_str_startswith (input, "a2f")) {
		return false;
	}
	static RCoreHelpMessage help_msg_a2f = {
		"Usage:", "a2f", "Experimental function analysis",
		"a2f", "", "like af, but with an experimental engine. see anal.a2f",
		NULL
	};
	if (!strncmp (input, "a2", 2)) {
		switch (input[2]) {
		case 'f':
			if (input[3] == '?') {
				anal->coreb.help (core, help_msg_a2f);
				return true;
			}

			if (!analyzeFunction (core, core->addr)) {
				R_LOG_DEBUG ("a2f: Failed to analyze function at 0x%08"PFMT64x, core->addr);
			}
			break;
		default:
			anal->coreb.help (core, help_msg_a2f);
			break;
		}
		return true;
	}
	return false;
}

// PLUGIN Definition Info
RAnalPlugin r_anal_plugin_a2f = {
	.meta = {
		.name = "a2f",
		.desc = "The reworked analysis from scratch thing",
		.license = "MIT",
	},
	.cmd = analcall,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_a2f,
	.version = R2_VERSION
};
#endif
