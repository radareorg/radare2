/* radare - Apache 2.0 - Copyright 2010-2019 - pancake and
 Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>

#include "../../../shlr/java/ops.h"
#include "../../../shlr/java/code.h"
#include "../../../shlr/java/class.h"

#define DO_THE_DBG 0
#define IFDBG  if(DO_THE_DBG)

static ut64 METHOD_START = 0;

static void java_update_anal_types (RAnal *anal, RBinJavaObj *bin_obj);

static int java_cmd_ext(RAnal *anal, const char* input);

static int java_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask);

static RBinJavaObj * get_java_bin_obj(RAnal *anal);

static RBinJavaObj * get_java_bin_obj(RAnal *anal) {
	RBin *b = anal->binb.bin;
	RBinPlugin *plugin = b->cur && b->cur->o ? b->cur->o->plugin : NULL;
	ut8 is_java = (plugin && strcmp (plugin->name, "java") == 0) ? 1 : 0;
	return is_java ? b->cur->o->bin_obj : NULL;
}

static ut64 java_get_method_start(void) {
	return METHOD_START;
}

static int java_switch_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut8 op_byte = data[0];
	ut64 offset = addr - java_get_method_start ();
	ut8 pos = (offset + 1)%4 ? 1 + 4 - (offset+1)%4 : 1;

	if (op_byte == 0xaa) {
		// handle a table switch condition
		if (pos + 8 + 8 > len) {
			return op->size;
		}
		const int min_val = (ut32)(UINT (data, pos + 4));
		const int max_val = (ut32)(UINT (data, pos + 8));

		ut32 default_loc = (ut32) (UINT (data, pos)), cur_case = 0;
		op->switch_op = r_anal_switch_op_new (addr, min_val, max_val, default_loc);
		pos += 12;
		if (max_val > min_val && ((max_val - min_val)<(UT16_MAX/4))) {
			//caseop = r_anal_switch_op_add_case(op->switch_op, addr+default_loc, -1, addr+offset);
			for (cur_case = 0; cur_case <= max_val - min_val; pos += 4, cur_case++) {
				//ut32 value = (ut32)(UINT (data, pos));
				if (pos + 4 >= len) {
					// switch is too big can't read further
					break;
				}
				int offset = (int)(ut32)(R_BIN_JAVA_UINT (data, pos));
				r_anal_switch_op_add_case (op->switch_op, addr + pos, cur_case + min_val, addr + offset);
			}
		} else {
			eprintf ("Invalid switch boundaries at 0x%"PFMT64x"\n", addr);
		}
	}
	op->size = pos;
	return op->size;
}


static ut64 extract_bin_op(ut64 ranal2_op_type) {
	ut64 bin_op_val = ranal2_op_type & (R_ANAL_JAVA_BIN_OP | 0x80000);
	switch (bin_op_val) {
	case R_ANAL_JAVA_BINOP_XCHG:return R_ANAL_OP_TYPE_XCHG;
	case R_ANAL_JAVA_BINOP_CMP: return R_ANAL_OP_TYPE_CMP;
	case R_ANAL_JAVA_BINOP_ADD: return R_ANAL_OP_TYPE_ADD;
	case R_ANAL_JAVA_BINOP_SUB: return R_ANAL_OP_TYPE_SUB;
	case R_ANAL_JAVA_BINOP_MUL: return R_ANAL_OP_TYPE_MUL;
	case R_ANAL_JAVA_BINOP_DIV: return R_ANAL_OP_TYPE_DIV;
	case R_ANAL_JAVA_BINOP_SHR: return R_ANAL_OP_TYPE_SHR;
	case R_ANAL_JAVA_BINOP_SHL: return R_ANAL_OP_TYPE_SHL;
	case R_ANAL_JAVA_BINOP_SAL: return R_ANAL_OP_TYPE_SAL;
	case R_ANAL_JAVA_BINOP_SAR: return R_ANAL_OP_TYPE_SAR;
	case R_ANAL_JAVA_BINOP_OR : return R_ANAL_OP_TYPE_OR;
	case R_ANAL_JAVA_BINOP_AND: return R_ANAL_OP_TYPE_AND;
	case R_ANAL_JAVA_BINOP_XOR: return R_ANAL_OP_TYPE_XOR;
	case R_ANAL_JAVA_BINOP_NOT: return R_ANAL_OP_TYPE_NOT;
	case R_ANAL_JAVA_BINOP_MOD: return R_ANAL_OP_TYPE_MOD;
	case R_ANAL_JAVA_BINOP_ROR: return R_ANAL_OP_TYPE_ROR;
	case R_ANAL_JAVA_BINOP_ROL: return R_ANAL_OP_TYPE_ROL;
	default: break;
	}
	return R_ANAL_OP_TYPE_UNK;
}




ut64 extract_unknown_op(ut64 ranal2_op_type) {
	if ((ranal2_op_type & R_ANAL_JAVA_CODEOP_JMP) == R_ANAL_JAVA_CODEOP_JMP) {
		return R_ANAL_OP_TYPE_UJMP;
	}
	if ((ranal2_op_type & R_ANAL_JAVA_CODEOP_CALL) == R_ANAL_JAVA_CODEOP_CALL) {
		return R_ANAL_OP_TYPE_UCALL;
	}
	if ((ranal2_op_type & R_ANAL_JAVA_LDST_OP_PUSH) == R_ANAL_JAVA_LDST_OP_PUSH) {
		return R_ANAL_OP_TYPE_UPUSH;
	}
	return R_ANAL_OP_TYPE_UNK;
}

static ut64 extract_code_op(ut64 ranal2_op_type) {
	ut64 conditional = R_ANAL_JAVA_COND_OP & ranal2_op_type ? R_ANAL_OP_TYPE_COND : 0;
	ut64 code_op_val = ranal2_op_type & (R_ANAL_JAVA_CODE_OP | 0x1FF);
	switch (code_op_val) {
	case R_ANAL_JAVA_CODEOP_CALL: return conditional | R_ANAL_OP_TYPE_CALL;
	case R_ANAL_JAVA_CODEOP_JMP: return conditional | R_ANAL_OP_TYPE_JMP;
	case R_ANAL_JAVA_CODEOP_RET: return conditional | R_ANAL_OP_TYPE_RET;
	case R_ANAL_JAVA_CODEOP_LEAVE: return R_ANAL_OP_TYPE_LEAVE;
	case R_ANAL_JAVA_CODEOP_SWI: return R_ANAL_OP_TYPE_SWI;
	case R_ANAL_JAVA_CODEOP_TRAP: return R_ANAL_OP_TYPE_TRAP;
	case R_ANAL_JAVA_CODEOP_SWITCH: return R_ANAL_OP_TYPE_SWITCH;
	}
	return R_ANAL_OP_TYPE_UNK;
}

ut64 extract_load_store_op(ut64 ranal2_op_type) {
	if ( (ranal2_op_type & R_ANAL_JAVA_LDST_OP_PUSH) == R_ANAL_JAVA_LDST_OP_PUSH) {
		return R_ANAL_OP_TYPE_PUSH;
	}
	if ( (ranal2_op_type & R_ANAL_JAVA_LDST_OP_POP) == R_ANAL_JAVA_LDST_OP_POP) {
		return R_ANAL_OP_TYPE_POP;
	}
	if ( (ranal2_op_type & R_ANAL_JAVA_LDST_OP_MOV) == R_ANAL_JAVA_LDST_OP_MOV) {
		return R_ANAL_OP_TYPE_MOV;
	}
	if ( (ranal2_op_type & R_ANAL_JAVA_LDST_OP_EFF_ADDR) == R_ANAL_JAVA_LDST_OP_EFF_ADDR) {
		return R_ANAL_OP_TYPE_LEA;
	}
	return R_ANAL_OP_TYPE_UNK;
}

static ut64 map_java_op_to_anal_op_type (ut64 t) {
	ut64 t2 = extract_bin_op(t);
	if (t2 != R_ANAL_OP_TYPE_UNK) {
		return t2;
	}
	switch (t) {
	case R_ANAL_JAVA_NULL_OP: return R_ANAL_OP_TYPE_NULL;
	case R_ANAL_JAVA_NOP: return R_ANAL_OP_TYPE_NOP;
	case R_ANAL_JAVA_BINOP_ADD: return R_ANAL_OP_TYPE_ADD;
	case R_ANAL_JAVA_BINOP_AND: return R_ANAL_OP_TYPE_AND;
	case R_ANAL_JAVA_BINOP_MUL: return R_ANAL_OP_TYPE_MUL;
	case R_ANAL_JAVA_BINOP_XOR: return R_ANAL_OP_TYPE_XOR;
	case R_ANAL_JAVA_BINOP_XCHG: return R_ANAL_OP_TYPE_MOV;
	case R_ANAL_JAVA_OBJOP_NEW: return R_ANAL_OP_TYPE_UCALL;
	case R_ANAL_JAVA_OBJOP_SIZE: return R_ANAL_OP_TYPE_UCALL;
	case R_ANAL_JAVA_ILL_OP: return R_ANAL_OP_TYPE_ILL;
	default:
		if (t & R_ANAL_JAVA_UNK_OP) {
			return extract_unknown_op (t);
		}
		if (t & R_ANAL_JAVA_CODE_OP) {
			return extract_code_op (t);
		}
		if (t & R_ANAL_JAVA_REP_OP) {
			ut64 ret = map_java_op_to_anal_op_type (t & ~R_ANAL_JAVA_REP_OP);
			return R_ANAL_OP_TYPE_REP | ret;
		}
		if (t & (R_ANAL_JAVA_LOAD_OP | R_ANAL_JAVA_STORE_OP)) {
			return extract_load_store_op(t);
		}
		if (t & R_ANAL_JAVA_BIN_OP) {
			return extract_bin_op (t);
		}
		break;
	}
	if (R_ANAL_JAVA_OBJOP_CAST & t) {
		return R_ANAL_OP_TYPE_MOV;
	}
	return R_ANAL_OP_TYPE_UNK;
}

static int r_anal_java_is_op_type_eop(ut64 x) {
	ut8 result = (x & R_ANAL_JAVA_CODE_OP) ? 1 : 0;
	return result &&
			( (x & R_ANAL_JAVA_CODEOP_LEAVE) == R_ANAL_JAVA_CODEOP_LEAVE ||
			 (x & R_ANAL_JAVA_CODEOP_RET) == R_ANAL_JAVA_CODEOP_RET ||
			 (x & R_ANAL_JAVA_CODEOP_JMP) == R_ANAL_JAVA_CODEOP_JMP ||
			 (x & R_ANAL_JAVA_CODEOP_SWITCH) == R_ANAL_JAVA_CODEOP_SWITCH);
}


static int java_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	/* get opcode size */
	if (len < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return 1;
	}
	//ut8 op_byte = data[0];
	ut8 op_byte = data[0];
	int sz = JAVA_OPS[op_byte].size;
	if (!op) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return sz;
	}
	IFDBG {
		//eprintf ("Extracting op from buffer (%d byte(s)) @ 0x%04x\n", len, addr);
		//eprintf ("Parsing op: (0x%02x) %s.\n", op_byte, JAVA_OPS[op_byte].name);
	}
	op->addr = addr;
	op->size = sz;
	op->id = data[0];
	op->type2 = JAVA_OPS[op_byte].op_type;
	op->type = map_java_op_to_anal_op_type (op->type2);
	// handle lookup and table switch offsets
	if (op_byte == 0xaa || op_byte == 0xab) {
		java_switch_op (anal, op, addr, data, len);
		// IN_SWITCH_OP = 1;
	}
	/* TODO:
	// not sure how to handle the states for IN_SWITCH_OP, SWITCH_OP_CASES,
	// and NUM_CASES_SEEN, because these are dependent on whether or not we
	// are in a switch, and given the non-reentrant state of opcode analysis
	// this can't always be guaranteed.  Below is the pseudo code for handling
	// the easy parts though
	if (IN_SWITCH_OP) {
		NUM_CASES_SEEN++;
		if (NUM_CASES_SEEN == SWITCH_OP_CASES) IN_SWITCH_OP=0;
		op->addr = addr;
		op->size = 4;
		op->type2 = 0;
		op->type = R_ANAL_OP_TYPE_CASE
		op->eob = 0;
		return op->sizes;
	}
	*/

	op->eob = r_anal_java_is_op_type_eop (op->type2);
	IFDBG {
		const char *ot_str = r_anal_optype_to_string (op->type);
		eprintf ("op_type2: %s @ 0x%04"PFMT64x" 0x%08"PFMT64x" op_type: (0x%02"PFMT64x") %s.\n",
			JAVA_OPS[op_byte].name, addr, (ut64)op->type2, (ut64)op->type,  ot_str);
		//eprintf ("op_eob: 0x%02x.\n", op->eob);
		//eprintf ("op_byte @ 0: 0x%02x op_byte @ 0x%04x: 0x%02x.\n", data[0], addr, data[addr]);
	}

	if (len < 4) {
		// incomplete analysis here
		return 0;
	}
	if (op->type == R_ANAL_OP_TYPE_POP) {
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 8;
	}
		op->direction = R_ANAL_OP_DIR_EXEC;
	if (op->type == R_ANAL_OP_TYPE_PUSH) {
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -8;
	}
	if (op->type == R_ANAL_OP_TYPE_CJMP) {
		op->jump = addr + (short)(USHORT (data, 1));
		op->fail = addr + sz;
		IFDBG eprintf ("%s jmpto 0x%04"PFMT64x"  failto 0x%04"PFMT64x".\n",
			JAVA_OPS[op_byte].name, op->jump, op->fail);
	} else if (op->type  == R_ANAL_OP_TYPE_JMP) {
		op->jump = addr + (short)(USHORT (data, 1));
		IFDBG eprintf ("%s jmpto 0x%04"PFMT64x".\n", JAVA_OPS[op_byte].name, op->jump);
	} else if ( (op->type & R_ANAL_OP_TYPE_CALL) == R_ANAL_OP_TYPE_CALL ) {
		op->jump = (int)(short)(USHORT (data, 1));
		op->fail = addr + sz;
		//IFDBG eprintf ("%s callto 0x%04x  failto 0x%04x.\n", JAVA_OPS[op_byte].name, op->jump, op->fail);
	}

	//r_java_disasm(addr, data, len, output, outlen);
	//IFDBG eprintf ("%s\n", output);
	return op->size;
}


static void java_update_anal_types (RAnal *anal, RBinJavaObj *bin_obj) {
	Sdb *D = anal->sdb_types;
	if (D && bin_obj) {
		RListIter *iter;
		char *str;
		RList * the_list = r_bin_java_extract_all_bin_type_values (bin_obj);
		if (the_list) {
			r_list_foreach (the_list, iter, str) {
				IFDBG eprintf ("Adding type: %s to known types.\n", str);
				if (str) {
					sdb_set (D, str, "type", 0);
				}
			}
		}
		r_list_free (the_list);
	}
}

static int java_cmd_ext(RAnal *anal, const char* input) {
	RBinJavaObj *obj = (RBinJavaObj *) get_java_bin_obj (anal);

	if (!obj) {
		eprintf ("Execute \"af\" to set the current bin, and this will bind the current bin\n");
		return -1;
	}
	switch (*input) {
	case 'c':
		// reset bytes counter for case operations
		r_java_new_method ();
		break;
	case 'u':
		switch (*(input+1)) {
			case 't': {java_update_anal_types (anal, obj); return true;}
			default: break;
		}
		break;
	case 's':
		switch (*(input+1)) {
			//case 'e': return java_resolve_cp_idx_b64 (anal, input+2);
			default: break;
		}
		break;

	default: eprintf("Command not supported"); break;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_java = {
	.name = "java",
	.desc = "Java bytecode analysis plugin",
	.license = "Apache",
	.arch = "java",
	.bits = 32,
	.op = &java_op,
	.cmd_ext = java_cmd_ext,
	0
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_java,
	.version = R2_VERSION
};
#endif
