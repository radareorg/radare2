/*
 * Convert from ESIL to REIL (Reverse Engineering Intermediate Language)
 * Contributor: sushant94
 */

#include <r_anal.h>

#define REIL_TEMP_PREFIX "V"
#define REIL_REG_PREFIX "R_"
#define REGBUFSZ 32

void reil_flag_spew_inst(RAnalEsil *esil, const char *flag);
static const char *ops[] = { FOREACHOP(REIL_OP_STRING) };

// Get size of a register.
static ut8 esil_internal_sizeof_reg(RAnalEsil *esil, const char *r) {
	if (!esil || !esil->anal || !esil->anal->reg || !r) {
		return false;
	}
	RRegItem *i = r_reg_get(esil->anal->reg, r, -1);
	return i ? (ut8)i->size : 0;
}

RAnalReilArgType reil_get_arg_type(RAnalEsil *esil, char *s) {
	if (!strncmp (s, REIL_TEMP_PREFIX, strlen (REIL_TEMP_PREFIX))) {
		return ARG_TEMP;
	}
	int type = r_anal_esil_get_parm_type(esil, s);
	switch (type) {
	case R_ANAL_ESIL_PARM_REG:
		return ARG_REG;
	case R_ANAL_ESIL_PARM_NUM:
		return ARG_CONST;
	default:
		return ARG_NONE;
	}
}

// Marshall the struct into a string
void reil_push_arg(RAnalEsil *esil, RAnalReilArg *op) {
	char *s = r_str_newf ("%s:%d", op->name, op->size);
	r_anal_esil_push (esil, s);
	free (s);
}

// Unmarshall the string in stack to the struct.
RAnalReilArg *reil_pop_arg(RAnalEsil *esil) {
	RAnalReilArg *op;
	int i, j = 0, flag = 0, len;
	char tmp_buf[REGBUFSZ];
	char *buf = r_anal_esil_pop(esil);
	if (!buf) {
		return NULL;
	}
	len = strlen (buf);
	op = R_NEW0(RAnalReilArg);
	for (i = 0; i < len; i++) {
		if (buf[i] == ':') {
			tmp_buf[j] = '\0';
			r_str_ncpy (op->name, tmp_buf, sizeof (op->name));
			memset (tmp_buf, 0, sizeof (tmp_buf));
			j = 0;
			flag = 1;
			continue;
		}
		// Strip all spaces
		if (buf[i] == ' ') {
			continue;
		}
		tmp_buf[j] = buf[i];
		j++;
	}
	tmp_buf[j] = '\0';

	// If we have not encountered a ':' we don't know the size yet.
	if (!flag) {
		r_str_ncpy (op->name, tmp_buf, sizeof (op->name));
		op->type = reil_get_arg_type (esil, op->name);
		if (op->type == ARG_REG) {
			op->size = esil_internal_sizeof_reg(esil, op->name);
		} else if (op->type == ARG_CONST) {
			op->size = esil->anal->bits;
		}
		free(buf);
		return op;
	}

	op->size = strtoll(tmp_buf, NULL, 10);
	op->type = reil_get_arg_type(esil, op->name);
	free(buf);
	return op;
}

// Get the next available temp register.
void get_next_temp_reg(RAnalEsil *esil, char *buf) {
	r_snprintf (buf, REGBUFSZ, REIL_TEMP_PREFIX"_%02"PFMT64u,
		esil->Reil->reilNextTemp);
	esil->Reil->reilNextTemp++;
}

void reil_make_arg(RAnalEsil *esil, RAnalReilArg *arg, char *name) {
	if (!arg) {
		return;
	}
	RAnalReilArgType type = reil_get_arg_type (esil, name);
	arg->size = 0;
	arg->type = type;
	r_str_ncpy  (arg->name, name, sizeof (arg->name) - 1);
}

// Free ins and all its arguments
void reil_free_inst(RAnalReilInst *ins) {
	if (!ins) {
		return;
	}
	if (ins->arg[0]) { R_FREE (ins->arg[0]); }
	if (ins->arg[1]) { R_FREE (ins->arg[1]); }
	if (ins->arg[2]) { R_FREE (ins->arg[2]); }
	R_FREE(ins);
}

// Automatically increments the seq_num of the instruction.
void reil_print_inst(RAnalEsil *esil, RAnalReilInst *ins) {
	int i;

	if (!ins || !esil) {
		return;
	}
	esil->anal->cb_printf("%04"PFMT64x".%02"PFMT64x": %8s",
		esil->Reil->addr, esil->Reil->seq_num++, ops[ins->opcode]);
	for (i = 0; i < 3; i++) {
		if (i > 0) {
			esil->anal->cb_printf (" ,");
		}
		if (!ins->arg[i]) {
			continue;
		}
		if (ins->arg[i]->type == ARG_NONE) {
			esil->anal->cb_printf ("%10s   ", ins->arg[i]->name);
			continue;
		}
		if (ins->arg[i]->type == ARG_REG) {
			char *tmp_buf = r_str_newf ("%s%s", REIL_REG_PREFIX, ins->arg[i]->name);
			esil->anal->cb_printf ("%10s:%02d", tmp_buf, ins->arg[i]->size);
			free (tmp_buf);
			continue;
		}
		esil->anal->cb_printf ("%10s:%02d", ins->arg[i]->name, ins->arg[i]->size);
	}
	esil->anal->cb_printf("\n");
}

// Used to cast sizes during assignment. OR is used for casting.
// Pushes the new *casted* src onto stack. Warning: Frees the original src!
void reil_cast_size(RAnalEsil *esil, RAnalReilArg *src, RAnalReilArg *dst) {
	char tmp_buf[REGBUFSZ];
	RAnalReilInst *ins;

	if (!src || !dst) {
		return;
	}
	// No need to case sizes if dst and src are of same size.
	if (src->size == dst->size) {
		reil_push_arg(esil, src);
		return;
	}
	snprintf (tmp_buf, REGBUFSZ-1, "0:%d", dst->size);
	r_anal_esil_push (esil, tmp_buf);
	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		return;
	}
	ins->opcode = REIL_OR;
	ins->arg[0] = src;
	ins->arg[1] = reil_pop_arg (esil);
	ins->arg[2] = R_NEW0(RAnalReilArg);
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg (esil, ins->arg[2], tmp_buf);
	if (ins->arg[2]) {
		ins->arg[2]->size = dst->size;
	}
	reil_print_inst (esil, ins);
	if (ins->arg[2]) {
		reil_push_arg (esil, ins->arg[2]);
	}
	reil_free_inst (ins);
}

// Here start translation functions!
static bool reil_eq(RAnalEsil *esil) {
	RAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	RAnalReilArgType src_type, dst_type;
	RAnalReilArg *dst, *src;

	dst = reil_pop_arg (esil);
	if (!dst) {
		return false;
	}
	src = reil_pop_arg (esil);
	if (!src) {
		R_FREE (dst);
		return false;
	}

	src_type = src->type;
	// Check if the src is an internal var. If it is, we need to resolve it.
	if (src_type == ARG_ESIL_INTERNAL) {
		reil_flag_spew_inst (esil, src->name + 1);
		R_FREE (src);
		src = reil_pop_arg (esil);
	} else if (src_type == ARG_REG) {
		// No direct register to register transfer.
		ins = R_NEW0 (RAnalReilInst);
		if (!ins) {
			free (src);
			free (dst);
			return false;
		}
		ins->opcode = REIL_STR;
		ins->arg[0] = src;
		ins->arg[1] = R_NEW0 (RAnalReilArg);
		if (!ins->arg[1]) {
			reil_free_inst (ins);
			return false;
		}
		ins->arg[2] = R_NEW0(RAnalReilArg);
		if (!ins->arg[2]) {
			reil_free_inst (ins);
			return false;
		}
		reil_make_arg (esil, ins->arg[1], " ");
		get_next_temp_reg (esil, tmp_buf);
		reil_make_arg (esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst (esil, ins);
		reil_push_arg( esil, ins->arg[2]);
		reil_free_inst (ins);
		src = reil_pop_arg (esil);
	}

	// First, make a copy of the dst. We will need this to set the flags later on.
	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		R_FREE (dst);
		R_FREE (src);
		return false;
	}
	dst_type = dst->type;
	if (src_type != ARG_ESIL_INTERNAL && dst_type == ARG_REG) {
		ins->opcode = REIL_STR;
		ins->arg[0] = dst;
		ins->arg[1] = R_NEW0 (RAnalReilArg);
		if (!ins->arg[1]) {
			reil_free_inst (ins);
			R_FREE (src);
			return false;
		}
		ins->arg[2] = R_NEW0 (RAnalReilArg);
		if (!ins->arg[2]) {
			reil_free_inst (ins);
			R_FREE (src);
			return false;
		}
		reil_make_arg (esil, ins->arg[1], " ");
		get_next_temp_reg (esil, tmp_buf);
		reil_make_arg (esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst (esil, ins);

		// Used for setting the flags
		r_snprintf (esil->Reil->old, sizeof (esil->Reil->old) - 1, "%s:%d",
				ins->arg[2]->name, ins->arg[2]->size);
		r_snprintf (esil->Reil->cur, sizeof (esil->Reil->cur) - 1, "%s:%d", dst->name,
				dst->size);
		esil->Reil->lastsz = dst->size;

		R_FREE (ins->arg[1]);
		R_FREE (ins->arg[2]);
	}

	// If we are modifying the Instruction Pointer, then we need to emit JCC instead.
	if (!strcmp(esil->Reil->pc, dst->name)) {
		ins->opcode = REIL_JCC;
		r_anal_esil_push (esil, "1:1");
		ins->arg[0] = reil_pop_arg (esil);
		ins->arg[1] = R_NEW0 (RAnalReilArg);
		reil_make_arg (esil, ins->arg[1], " ");
		ins->arg[2] = src;
		reil_print_inst (esil, ins);
		reil_free_inst (ins);
		R_FREE (dst);
		return true;
	}

	reil_cast_size (esil, src, dst);
	ins->opcode = REIL_STR;
	ins->arg[0] = reil_pop_arg (esil);
	if (!ins->arg[0]) {
		R_FREE (dst);
		reil_free_inst (ins);
		return false;
	}

	ins->arg[2] = dst;
	ins->arg[1] = R_NEW0 (RAnalReilArg);
	reil_make_arg (esil, ins->arg[1], " ");
	reil_print_inst (esil, ins);
	reil_free_inst (ins);
	return true;
}

// General function for operations that take 2 operands
static int reil_binop(RAnalEsil *esil, RAnalReilOpcode opcode) {
	RAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	ut8 dst_size;
	RAnalReilArg *op2, *op1;

	op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg(esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}

	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		R_FREE (op1);
		R_FREE (op2);
		return false;
	}
	ins->opcode = opcode;
	ins->arg[0] = op2;
	ins->arg[1] = op1;
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = R_NEW0(RAnalReilArg);
	if (!ins->arg[2])  {
		reil_free_inst (ins);
		return false;
	}
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	// Choose the larger of the two sizes as the size of dst
	dst_size = ins->arg[0]->size;
	if (dst_size < ins->arg[1]->size) {
		dst_size = ins->arg[1]->size;
	}
	// REIL_LT has a dst_size of 1.
	if (opcode == REIL_LT) {
		dst_size = 1;
	}
	ins->arg[2]->size = dst_size;
	reil_print_inst(esil, ins);
	reil_push_arg(esil, ins->arg[2]);
	reil_free_inst(ins);
	return true;
}

// General function for operations which re-assign to dst. Example, addeq.
static int reil_bineqop(RAnalEsil *esil, RAnalReilOpcode opcode) {
	int ret = 1;
	RAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}

	reil_push_arg(esil, op);
	ret &= reil_binop(esil, opcode);
	reil_push_arg(esil, op);
	ret &= reil_eq(esil);
	R_FREE(op);
	return ret;
}

static bool reil_add(RAnalEsil *esil)     { return reil_binop (esil, REIL_ADD);   }
static bool reil_addeq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_ADD); }
static bool reil_mul(RAnalEsil *esil)     { return reil_binop (esil, REIL_MUL);   }
static bool reil_muleq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_MUL); }
static bool reil_sub(RAnalEsil *esil)     { return reil_binop (esil, REIL_SUB);   }
static bool reil_subeq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_SUB); }
static bool reil_div(RAnalEsil *esil)     { return reil_binop (esil, REIL_DIV);   }
static bool reil_diveq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_DIV); }
static bool reil_xor(RAnalEsil *esil)     { return reil_binop (esil, REIL_XOR);   }
static bool reil_xoreq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_XOR); }
static bool reil_and(RAnalEsil *esil)     { return reil_binop (esil, REIL_AND);   }
static bool reil_andeq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_AND); }
static bool reil_or(RAnalEsil *esil)      { return reil_binop (esil, REIL_OR);    }
static bool reil_oreq(RAnalEsil *esil)    { return reil_bineqop (esil, REIL_OR);  }
static bool reil_lsl(RAnalEsil *esil)     { return reil_binop (esil, REIL_SHL);   }
static bool reil_lsleq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_SHL); }
static bool reil_lsr(RAnalEsil *esil)     { return reil_binop (esil, REIL_SHR);   }
static bool reil_lsreq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_SHR); }
static bool reil_smaller(RAnalEsil *esil) { return reil_binop (esil, REIL_LT);    }

static bool reil_cmp(RAnalEsil *esil) {
	RAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	RAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}

	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		R_FREE (op1);
		R_FREE (op2);
		return false;
	}
	ins->opcode = REIL_EQ;
	ins->arg[0] = op2;
	ins->arg[1] = op1;
	ins->arg[2] = R_NEW0 (RAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg (esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = 1;
	reil_print_inst (esil, ins);
	// Set vars needed to determine flags.
	r_snprintf (esil->Reil->cur, sizeof (esil->Reil->old) - 1, "%s:%d",
			ins->arg[2]->name, ins->arg[2]->size);
	r_snprintf (esil->Reil->old, sizeof (esil->Reil->cur) - 1, "%s:%d",
			op2->name, op2->size);
	if (r_reg_get (esil->anal->reg, op2->name, -1)) {
		esil->Reil->lastsz = op2->size;
	} else if (r_reg_get (esil->anal->reg, op1->name, -1)) {
		esil->Reil->lastsz = op1->size;
	}
	reil_push_arg (esil, ins->arg[2]);
	reil_free_inst (ins);
	return true;
}

static bool reil_smaller_equal(RAnalEsil *esil) {
	RAnalReilArg *op2, *op1;

	op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg(esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}

	reil_push_arg(esil, op1);
	reil_push_arg(esil, op2);
	reil_smaller(esil);
	reil_push_arg(esil, op1);
	reil_push_arg(esil, op2);
	reil_cmp(esil);
	reil_or(esil);

	R_FREE(op1);
	R_FREE(op2);
	return true;
}

static bool reil_larger(RAnalEsil *esil) {
	RAnalReilArg *op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}
	reil_push_arg (esil, op2);
	reil_push_arg (esil, op1);
	reil_smaller (esil);
	R_FREE (op1);
	R_FREE (op2);
	return true;
}

static bool reil_larger_equal(RAnalEsil *esil) {
	RAnalReilArg *op2, *op1;

	op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg(esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}

	reil_push_arg (esil, op2);
	reil_push_arg (esil, op1);
	reil_smaller_equal (esil);
	R_FREE (op1);
	R_FREE (op2);
	return true;
}

static bool reil_dec(RAnalEsil *esil) {
	RAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}
	r_anal_esil_pushnum (esil, 1);
	reil_push_arg (esil, op);
	reil_sub (esil);
	R_FREE (op);
	return true;
}

static bool reil_deceq(RAnalEsil *esil) {
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}
	reil_push_arg (esil, op1);
	reil_dec (esil);
	reil_push_arg (esil, op1);
	reil_eq (esil);
	R_FREE (op1);
	return true;
}

static bool reil_inc(RAnalEsil *esil) {
	RAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}

	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op);
	reil_add(esil);
	R_FREE(op);
	return true;
}

static bool reil_inceq(RAnalEsil *esil) {
	RAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}
	reil_push_arg (esil, op);
	reil_inc (esil);
	reil_push_arg (esil, op);
	reil_eq (esil);
	R_FREE (op);
	return true;
}

static bool reil_neg(RAnalEsil *esil) {
	char tmp_buf[REGBUFSZ];
	RAnalReilInst *ins;
	RAnalReilArg *op = reil_pop_arg (esil);
	if (!op) {
		return false;
	}
	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		R_FREE (op);
		return false;
	}
	ins->opcode = REIL_EQ;
	ins->arg[0] = op;
	r_anal_esil_pushnum (esil, 0);
	ins->arg[1] = reil_pop_arg(esil);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = R_NEW0 (RAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	if (ins->arg[0]->size < ins->arg[1]->size) {
		ins->arg[1]->size = ins->arg[0]->size;
	}

	ins->arg[2]->size = 1;
	reil_print_inst (esil, ins);
	reil_push_arg (esil, ins->arg[2]);
	reil_free_inst (ins);
	return true;
}

static bool reil_negeq(RAnalEsil *esil) {
	RAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}
	reil_push_arg (esil, op);
	reil_neg (esil);
	reil_push_arg (esil, op);
	reil_eq (esil);
	free (op);
	return true;
}

static bool reil_not(RAnalEsil *esil) {
	char tmp_buf[REGBUFSZ];
	RAnalReilInst *ins;
	RAnalReilArg *op = reil_pop_arg (esil);
	if (!op) {
		return false;
	}

	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		R_FREE (op);
		return false;
	}
	ins->opcode = REIL_NOT;
	ins->arg[0] = op;
	ins->arg[1] = R_NEW0 (RAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = R_NEW0 (RAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg (esil, ins->arg[1], " ");
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg (esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = ins->arg[0]->size;
	reil_print_inst (esil, ins);
	reil_push_arg (esil, ins->arg[2]);
	reil_free_inst (ins);
	return true;
}

static bool reil_if(RAnalEsil *esil) {
	RAnalReilInst *ins;
	RAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}

	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		R_FREE (op2);
		R_FREE (op1);
		return false;
	}
	ins->opcode = REIL_JCC;
	ins->arg[0] = op1;
	ins->arg[2] = op2;
	ins->arg[1] = R_NEW0 (RAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg (esil, ins->arg[1], " ");
	reil_print_inst (esil, ins);
	reil_free_inst (ins);
	return true;
}

static bool reil_if_end(RAnalEsil *esil) { return true; }

static bool reil_peek(RAnalEsil *esil) {
	RAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}

	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		R_FREE (op1);
		return false;
	}
	ins->opcode = REIL_LDM;
	ins->arg[0] = op1;
	ins->arg[1] = R_NEW0(RAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = R_NEW0(RAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg(esil, ins->arg[1], " ");
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = ins->arg[0]->size;
	reil_print_inst(esil, ins);
	reil_push_arg(esil, ins->arg[2]);
	reil_free_inst(ins);
	return true;
}

// n = 8, 4, 2, 1
static bool reil_peekn(RAnalEsil *esil, ut8 n) {
	RAnalReilArg *op2;
	RAnalReilArg *op1 = reil_pop_arg (esil);
	if (!op1) {
		return false;
	}

	reil_push_arg (esil, op1);
	reil_peek (esil);
	// No need to cast if n = 0
	if (n == 0) {
		R_FREE (op1);
		return true;
	}

	R_FREE (op1);
	op1 = reil_pop_arg (esil);
	if (!op1) {
		return false;
	}

	op2 = R_NEW0 (RAnalReilArg);
	if (!op2) {
		R_FREE (op1);
		return false;
	}
	op2->size = n * 8;
	op2->type = ARG_TEMP;
	get_next_temp_reg (esil, op2->name);
	reil_cast_size (esil, op1, op2);
	esil->Reil->lastsz = 8 * n;

	R_FREE (op2);
	return true;
}

static bool reil_peek1(RAnalEsil *esil) { return reil_peekn(esil, 1); }
static bool reil_peek2(RAnalEsil *esil) { return reil_peekn(esil, 2); }
static bool reil_peek4(RAnalEsil *esil) { return reil_peekn(esil, 4); }
static bool reil_peek8(RAnalEsil *esil) { return reil_peekn(esil, 8); }

// n = 8, 4, 2, 1
static bool reil_poken(RAnalEsil *esil, ut8 n) {
	char tmp_buf[REGBUFSZ];
	RAnalReilInst *ins;
	RAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}

	if (op1->type != ARG_ESIL_INTERNAL) {
		ins = R_NEW0 (RAnalReilInst);
		if (!ins) {
			R_FREE (op2);
			R_FREE (op1);
			return false;
		}
		ins->opcode = REIL_LDM;
		ins->arg[0] = op2;
		ins->arg[1] = R_NEW0(RAnalReilArg);
		if (!ins->arg[1]) {
			R_FREE (op1);
			reil_free_inst (ins);
			return false;
		}
		ins->arg[2] = R_NEW0(RAnalReilArg);
		if (!ins->arg[2]) {
			R_FREE (op1);
			reil_free_inst (ins);
			return false;
		}
		reil_make_arg (esil, ins->arg[1], " ");
		get_next_temp_reg (esil, tmp_buf);
		reil_make_arg (esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst (esil, ins);
		r_snprintf (esil->Reil->old, sizeof (esil->Reil->old) - 1, "%s:%d",
				ins->arg[2]->name, ins->arg[2]->size);
		r_snprintf (esil->Reil->cur, sizeof (esil->Reil->cur) - 1, "%s:%d",
				op2->name, op2->size);
		esil->lastsz = n * 8;
		reil_push_arg (esil, op1);
		reil_push_arg (esil, op2);
		R_FREE (op1);
		reil_free_inst (ins);
	} else {
		reil_flag_spew_inst (esil, op1->name + 1);
		R_FREE (op1);
		op1 = reil_pop_arg (esil);
		reil_push_arg (esil, op2);
		reil_push_arg (esil, op1);
		R_FREE (op2);
		R_FREE (op1);
	}

	ins = R_NEW0 (RAnalReilInst);
	if (!ins) {
		return false;
	}
	ins->opcode = REIL_STM;
	ins->arg[2] = reil_pop_arg (esil);
	ins->arg[0] = reil_pop_arg (esil);
	ins->arg[1] = R_NEW0 (RAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg(esil, ins->arg[1], " ");
	reil_print_inst(esil, ins);
	reil_free_inst(ins);
	return true;
}

static bool reil_poke(RAnalEsil *esil) {
	return reil_poken (esil, esil->anal->bits / 8);
}

static bool reil_poke1(RAnalEsil *esil) { return reil_poken(esil, 1); }
static bool reil_poke2(RAnalEsil *esil) { return reil_poken(esil, 2); }
static bool reil_poke4(RAnalEsil *esil) { return reil_poken(esil, 4); }
static bool reil_poke8(RAnalEsil *esil) { return reil_poken(esil, 8); }

// Generic function to handle all mem_*eq_n functions. Example, mem_oreq_n
static bool reil_mem_bineq_n(RAnalEsil *esil, RAnalReilOpcode opcode, ut8 size) {
	int ret = 1;
	RAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		R_FREE (op2);
		return false;
	}

	reil_push_arg(esil, op2);
	ret &= reil_peekn(esil, size);
	reil_push_arg(esil, op1);
	ret &= reil_binop(esil, opcode);
	reil_push_arg(esil, op2);
	ret &= reil_poken(esil, size);

	free (op2);
	free (op1);
	return ret;
}

static bool reil_mem_oreq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_OR, esil->anal->bits / 8); }
static bool reil_mem_oreq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 1); }
static bool reil_mem_oreq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 2); }
static bool reil_mem_oreq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 4); }
static bool reil_mem_oreq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 8); }

static bool reil_mem_andeq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_AND, esil->anal->bits / 8); }
static bool reil_mem_andeq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 1); }
static bool reil_mem_andeq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 2); }
static bool reil_mem_andeq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 4); }
static bool reil_mem_andeq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 8); }

static bool reil_mem_xoreq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_XOR, esil->anal->bits / 8); }
static bool reil_mem_xoreq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 1); }
static bool reil_mem_xoreq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 2); }
static bool reil_mem_xoreq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 4); }
static bool reil_mem_xoreq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 8); }

static bool reil_mem_addeq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_ADD, esil->anal->bits / 8); }
static bool reil_mem_addeq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 1); }
static bool reil_mem_addeq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 2); }
static bool reil_mem_addeq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 4); }
static bool reil_mem_addeq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 8); }

static bool reil_mem_subeq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_SUB, esil->anal->bits / 8); }
static bool reil_mem_subeq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 1); }
static bool reil_mem_subeq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 2); }
static bool reil_mem_subeq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 4); }
static bool reil_mem_subeq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 8); }

static bool reil_mem_muleq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_MUL, esil->anal->bits / 8); }
static bool reil_mem_muleq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 1); }
static bool reil_mem_muleq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 2); }
static bool reil_mem_muleq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 4); }
static bool reil_mem_muleq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 8); }

static bool reil_mem_inceq_n(RAnalEsil *esil, ut8 size) {
	int ret = 1;
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}

	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op1);
	ret &= reil_mem_bineq_n(esil, REIL_ADD, size);

	free (op1);
	return ret;
}

static bool reil_mem_inceq(RAnalEsil *esil) {
	return reil_mem_inceq_n(esil, esil->anal->bits / 8);
}
static bool reil_mem_inceq1(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 1); }
static bool reil_mem_inceq2(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 2); }
static bool reil_mem_inceq4(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 4); }
static bool reil_mem_inceq8(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 8); }

static int reil_mem_deceq_n(RAnalEsil *esil, ut8 size) {
	int ret = 1;
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}

	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op1);
	ret &= reil_mem_bineq_n(esil, REIL_SUB, size);

	free (op1);
	return ret;
}

static bool reil_mem_deceq(RAnalEsil *esil) {
	return reil_mem_deceq_n(esil, esil->anal->bits / 8);
}
static bool reil_mem_deceq1(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 1); }
static bool reil_mem_deceq2(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 2); }
static bool reil_mem_deceq4(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 4); }
static bool reil_mem_deceq8(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 8); }

// Functions to resolve internal vars.
// performs (2 << op) - 1
void reil_generate_mask(RAnalEsil *esil) {
	r_anal_esil_pushnum(esil, 2);
	reil_lsl(esil);
	reil_dec(esil);
}

void reil_generate_borrow_flag(RAnalEsil *esil, ut8 bit) {
	RAnalReilArg *op1;

	r_anal_esil_pushnum(esil, bit);
	r_anal_esil_pushnum(esil, 0x3f);
	reil_and(esil);
	r_anal_esil_pushnum(esil, 0x3f);
	reil_add(esil);
	r_anal_esil_pushnum(esil, 0x3f);
	reil_and(esil);
	// Generate the mask. 2 << bits - 1
	reil_generate_mask(esil);
	op1 = reil_pop_arg(esil);
	// old & mask
	r_anal_esil_push(esil, esil->Reil->old);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// cur & mask
	r_anal_esil_push(esil, esil->Reil->cur);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// Check
	reil_larger(esil);

	free (op1);
}

void reil_generate_carry_flag(RAnalEsil *esil, ut8 bit) {
	RAnalReilArg *op1;

	r_anal_esil_pushnum(esil, bit);
	r_anal_esil_pushnum(esil, 0x3f);
	reil_and(esil);
	// Generate the mask. 2 << bits - 1
	reil_generate_mask(esil);
	op1 = reil_pop_arg(esil);
	// old & mask
	r_anal_esil_push(esil, esil->Reil->old);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// cur & mask
	r_anal_esil_push(esil, esil->Reil->cur);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// Check
	reil_smaller(esil);

	free (op1);
}

void reil_generate_partity_flag(RAnalEsil *esil) {
	// Generation of parity flag taken from openreil README example.
	RAnalReilArg *op;
	r_anal_esil_push(esil, esil->Reil->cur);
	r_anal_esil_pushnum(esil, 0xff);
	reil_and(esil);
	op = reil_pop_arg(esil);
	if (!op) {
		return;
	}

	r_anal_esil_pushnum(esil, 7);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	r_anal_esil_pushnum(esil, 6);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_xor(esil);
	r_anal_esil_pushnum(esil, 5);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	r_anal_esil_pushnum(esil, 4);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_xor(esil);
	reil_xor(esil);
	r_anal_esil_pushnum(esil, 3);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	r_anal_esil_pushnum(esil, 2);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_xor(esil);
	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_push_arg(esil, op);
	reil_xor(esil);
	reil_xor(esil);
	reil_xor(esil);
	r_anal_esil_pushnum(esil, 1);
	reil_and(esil);
	reil_not(esil);

	free (op);
}

void reil_generate_signature(RAnalEsil *esil) {
	if (!esil->Reil->lastsz || esil->Reil->lastsz == 0) {
		r_anal_esil_pushnum(esil, 0);
		return;
	}

	RAnalReilArg *op;

	r_anal_esil_pushnum(esil, esil->Reil->lastsz - 1);
	r_anal_esil_pushnum(esil, 1);
	reil_lsl(esil);
	r_anal_esil_push(esil, esil->Reil->cur);
	reil_and(esil);

	op = reil_pop_arg(esil);
	if (!op) {
		return;
	}

	r_anal_esil_pushnum(esil, esil->Reil->lastsz - 1);
	reil_push_arg(esil, op);
	reil_lsr(esil);

	free (op);
}

void reil_generate_overflow_flag(RAnalEsil *esil) {
	if (esil->Reil->lastsz < 2) {
		r_anal_esil_pushnum (esil, 0);
	}

	reil_generate_borrow_flag(esil, esil->Reil->lastsz);
	reil_generate_carry_flag(esil, esil->Reil->lastsz - 2);
	reil_xor(esil);
}

void reil_flag_spew_inst(RAnalEsil *esil, const char *flag) {
	ut8 bit;
	switch (flag[0]) {
		case 'z': // zero-flag
			r_anal_esil_push(esil, esil->Reil->cur);
			break;
		case 'b':
			bit = (ut8)r_num_get(NULL, &flag[1]);
			reil_generate_borrow_flag(esil, bit);
			break;
		case 'c':
			bit = (ut8)r_num_get(NULL, &flag[1]);
			reil_generate_carry_flag(esil, bit);
			break;
		case 'o':
			reil_generate_overflow_flag(esil);
			break;
		case 'p':
			reil_generate_partity_flag(esil);
			break;
		case 'r':
			r_anal_esil_pushnum(esil, esil->anal->bits / 8);
			break;
		case 's':
			reil_generate_signature(esil);
			break;
		default:
			return;
	}

	return;
}

/* Callback hook for command_hook */
static int setup_reil_ins(RAnalEsil *esil, const char *op) {
	esil->Reil->addr++;      // Increment the address location.
	esil->Reil->seq_num = 0; // Reset the sequencing.
	return 0;
}

R_API int r_anal_esil_to_reil_setup(RAnalEsil *esil, RAnal *anal, int romem,
		int stats) {
	if (!esil) {
		return false;
	}
	esil->verbose = 2;
	esil->anal = anal;
	esil->trap = 0;
	esil->trap_code = 0;

	/* Set up a callback for hook_command */
	esil->cb.hook_command = setup_reil_ins;

	esil->Reil = R_NEW0(RAnalReil);
	if (!esil->Reil) {
		return false;
	}
	esil->Reil->reilNextTemp = 0;
	esil->Reil->addr = -1;
	esil->Reil->seq_num = 0;
	esil->Reil->skip = 0;

	// Store the pc
	const char *name = r_reg_get_name (esil->anal->reg, r_reg_get_name_idx ("PC"));
	strncpy (esil->Reil->pc, name, sizeof (esil->Reil->pc) - 1);

	r_anal_esil_mem_ro(esil, romem);

#define	OT_UNK	R_ANAL_ESIL_OP_TYPE_UNKNOWN
#define	OT_CTR	R_ANAL_ESIL_OP_TYPE_CONTROL_FLOW
#define	OT_MATH	R_ANAL_ESIL_OP_TYPE_MATH
#define	OT_REGW	R_ANAL_ESIL_OP_TYPE_REG_WRITE
#define	OT_MEMW	R_ANAL_ESIL_OP_TYPE_MEM_WRITE
#define	OT_MEMR	R_ANAL_ESIL_OP_TYPE_MEM_READ

	r_anal_esil_set_op(esil, "=", reil_eq, 0, 2, OT_REGW);
	r_anal_esil_set_op(esil, "+", reil_add, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "+=", reil_addeq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "-", reil_sub, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "-=", reil_subeq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "*", reil_mul, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "*=", reil_muleq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "/", reil_div, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "/=", reil_diveq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "^", reil_xor, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "^=", reil_xoreq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "|", reil_or, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "|=", reil_oreq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "&", reil_and, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "&=", reil_andeq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "<<", reil_lsl, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "<<=", reil_lsleq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, ">>", reil_lsr, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, ">>=", reil_lsreq, 0, 2, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "++=", reil_inceq, 0, 1, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "++", reil_inc, 1, 1, OT_MATH);
	r_anal_esil_set_op(esil, "--=", reil_deceq, 0, 1, OT_MATH | OT_REGW);
	r_anal_esil_set_op(esil, "--", reil_dec, 1, 1, OT_MATH);
	r_anal_esil_set_op(esil, "!", reil_neg, 1, 1, OT_MATH);
	r_anal_esil_set_op(esil, "!=", reil_negeq, 0, 1, OT_MATH);
	r_anal_esil_set_op(esil, "==", reil_cmp, 0, 2, OT_MATH);
	r_anal_esil_set_op(esil, "<", reil_smaller, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, ">", reil_larger, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "<=", reil_smaller_equal, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, ">=", reil_larger_equal, 1, 2, OT_MATH);
	r_anal_esil_set_op(esil, "[]", reil_peek, 1, 1, OT_MEMR);
	r_anal_esil_set_op(esil, "=[]", reil_poke, 0, 2, OT_MEMW);
	r_anal_esil_set_op(esil, "|=[]", reil_mem_oreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "^=[]", reil_mem_xoreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "&=[]", reil_mem_andeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "+=[]", reil_mem_addeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "-=[]", reil_mem_subeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "*=[]", reil_mem_muleq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "++=[]", reil_mem_inceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "--=[]", reil_mem_deceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "=[1]", reil_poke1, 0, 2, OT_MEMW);
	r_anal_esil_set_op(esil, "=[2]", reil_poke2, 0, 2, OT_MEMW);
	r_anal_esil_set_op(esil, "=[4]", reil_poke4, 0, 2, OT_MEMW);
	r_anal_esil_set_op(esil, "=[8]", reil_poke8, 0, 2, OT_MEMW);
	r_anal_esil_set_op(esil, "[1]", reil_peek1, 1, 1, OT_MEMR);
	r_anal_esil_set_op(esil, "[2]", reil_peek2, 1, 1, OT_MEMR);
	r_anal_esil_set_op(esil, "[4]", reil_peek4, 1, 1, OT_MEMR);
	r_anal_esil_set_op(esil, "[8]", reil_peek8, 1, 1, OT_MEMR);
	r_anal_esil_set_op(esil, "|=[1]", reil_mem_oreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "|=[2]", reil_mem_oreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "|=[4]", reil_mem_oreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "|=[8]", reil_mem_oreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "^=[1]", reil_mem_xoreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "^=[2]", reil_mem_xoreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "^=[4]", reil_mem_xoreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "^=[8]", reil_mem_xoreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "&=[1]", reil_mem_andeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "&=[2]", reil_mem_andeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "&=[4]", reil_mem_andeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "&=[8]", reil_mem_andeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "+=[1]", reil_mem_addeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "+=[2]", reil_mem_addeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "+=[4]", reil_mem_addeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "+=[8]", reil_mem_addeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "-=[1]", reil_mem_subeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "-=[2]", reil_mem_subeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "-=[4]", reil_mem_subeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "-=[8]", reil_mem_subeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "*=[1]", reil_mem_muleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "*=[2]", reil_mem_muleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "*=[4]", reil_mem_muleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "*=[8]", reil_mem_muleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "++=[1]", reil_mem_inceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "++=[2]", reil_mem_inceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "++=[4]", reil_mem_inceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "++=[8]", reil_mem_inceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "--=[1]", reil_mem_deceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "--=[2]", reil_mem_deceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "--=[4]", reil_mem_deceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "--=[8]", reil_mem_deceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	r_anal_esil_set_op(esil, "?{", reil_if, 0, 1, OT_CTR);
	r_anal_esil_set_op(esil, "}", reil_if_end, 0, 0, OT_CTR);

	return true;
}
