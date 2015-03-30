/*
 * Convert from ESIL to REIL (Reverse Engineering Intermediate Language)
 * Contributor: sushant94
 */

#include <r_anal.h>

#define REIL_TEMP_PREFIX "V"
void reil_flag_spew_inst(RAnalEsil *esil, const char *flag);
const char *ops[] = { FOREACHOP(REIL_OP_STRING) };

// Get size of a register.
static ut8 esil_internal_sizeof_reg(RAnalEsil *esil, const char *r) {
	RRegItem *i;
	if (!esil || !esil->anal || !esil->anal->reg || !r)
		return R_FALSE;
	i = r_reg_get(esil->anal->reg, r, -1);
	if (!i)
		return R_FALSE;
	return (ut8)i->size;
}

RAnalReilArgType reil_get_arg_type(RAnalEsil *esil, char *s) {
	if (!strncmp(s, REIL_TEMP_PREFIX, strlen(REIL_TEMP_PREFIX)))
		return ARG_TEMP;

	int type = r_anal_esil_get_parm_type(esil, s);

	switch (type) {
		case R_ANAL_ESIL_PARM_REG:
			return ARG_REG;
		case R_ANAL_ESIL_PARM_NUM:
			return ARG_CONST;
		case R_ANAL_ESIL_PARM_INTERNAL:
			return ARG_ESIL_INTERNAL;
		default:
			return ARG_NONE;
	}
}

// Marshall the struct into a string
void reil_push_arg(RAnalEsil *esil, RAnalReilArg *op) {
	char tmp_buf[32];
	snprintf(tmp_buf, sizeof(tmp_buf), "%s:%d", op->name, op->size);
	r_anal_esil_push(esil, tmp_buf);
}

// Unmarshall the string in stack to the struct.
RAnalReilArg *reil_pop_arg(RAnalEsil *esil) {
	RAnalReilArg *op;
	int i, j = 0, flag = 0, len;
	char tmp_buf[32];
	char *buf = r_anal_esil_pop(esil);
	if (!buf) return NULL;

	len = strlen(buf);
	op = R_NEW0(RAnalReilArg);

	for (i = 0; i < len; i++) {
		if (buf[i] == ':') {
			tmp_buf[j] = '\0';
			strncpy(op->name, tmp_buf, sizeof(op->name));
			memset(tmp_buf, 0, sizeof(tmp_buf));
			j = 0;
			flag = 1;
			continue;
		}
		// Strip all spaces
		if (buf[i] == ' ') continue;
		tmp_buf[j] = buf[i];
		j++;
	}

	tmp_buf[j] = '\0';

	// If we have not encountered a ':' we don't know the size yet.
	if (!flag) {
		strncpy(op->name, tmp_buf, sizeof(op->name));
		op->type = reil_get_arg_type(esil, op->name);
		if (op->type == ARG_REG) 
			op->size = esil_internal_sizeof_reg(esil, op->name);
		else if (op->type == ARG_CONST)
			op->size = esil->anal->bits;
		return op;
	}

	op->size = atoi(tmp_buf);
	op->type = reil_get_arg_type(esil, op->name);
	return op;
}

// Get the next available temp register.
void get_next_temp_reg(RAnalEsil *esil, char *buf) {
	int n;
	n = esil->Reil->reilNextTemp;
	snprintf(buf, sizeof(buf), "%s_%02d", REIL_TEMP_PREFIX, n);
	esil->Reil->reilNextTemp++;
}

void reil_make_arg(RAnalEsil *esil, RAnalReilArg *arg, char *name) {
	if (!arg)
		return;

	RAnalReilArgType type;
	type = reil_get_arg_type(esil, name);
	arg->size = 0;
	arg->type = type;
	memset(arg->name, 0, sizeof(arg->name));
	strncpy(arg->name, name, sizeof(arg->name));
}

RAnalReilInst *reil_new_inst(RAnalEsil *esil) {
	RAnalReilInst *ins;
	ins = R_NEW0(RAnalReilInst);

	if (!ins) return NULL;

	ins->addr = esil->Reil->addr;
	ins->seq_num = esil->Reil->seq_num++;
	return ins;
}

// Automatically increments the seq_num of the instruction.
void reil_print_inst(RAnalEsil *esil, RAnalReilInst *ins) {
	if (!ins)
		return;

	if (ins->arg[1]->type != ARG_NONE) {
		printf("%04llx.%03llx: %14s  %14s:%d, %14s:%d, %14s:%d\n", ins->addr,
				ins->seq_num, ops[ins->opcode], ins->arg[0]->name,
				ins->arg[0]->size, ins->arg[1]->name, ins->arg[1]->size,
				ins->arg[2]->name, ins->arg[2]->size);
	} else {
		printf("%04llx.%03llx: %14s  %14s:%d, %14s   , %14s:%d\n", ins->addr,
				ins->seq_num, ops[ins->opcode], ins->arg[0]->name,
				ins->arg[0]->size, ins->arg[1]->name, ins->arg[2]->name,
				ins->arg[2]->size);
	}

	ins->seq_num++;
}

// Used to cast sizes during assignment. OR is used for casting.
void reil_cast_size(RAnalEsil *esil, RAnalReilArg *src, RAnalReilArg *dst) {
	// No need to case sizes if dst and src are of same size.
	if (src->size == dst->size) {
		reil_push_arg(esil, src);
		return;
	}

	char tmp_buf[32];
	RAnalReilInst *ins;

	snprintf(tmp_buf, sizeof(tmp_buf), "0:%d", dst->size);
	r_anal_esil_push (esil, tmp_buf);

	ins = reil_new_inst(esil);
	ins->opcode = REIL_OR;

	ins->arg[0] = src;
	ins->arg[1] = reil_pop_arg (esil);
	ins->arg[2] = R_NEW0(RAnalReilArg);
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = dst->size;

	reil_print_inst(esil, ins);
	reil_push_arg(esil, ins->arg[2]);

	free (ins->arg[1]);
	free (ins->arg[2]);
	free (ins);
}

// Here start translation functions!
static int reil_eq(RAnalEsil *esil) {
	RAnalReilInst *ins;
	char tmp_buf[32];
	RAnalReilArgType src_type, dst_type;
	RAnalReilArg *dst = reil_pop_arg(esil);
	RAnalReilArg *src = reil_pop_arg(esil);

	if (!src || !dst) return R_FALSE;

	ins = reil_new_inst(esil);
	src_type = src->type;

	// Check if the src is an internal var. If it is, we need to resolve it.
	if (src_type == ARG_ESIL_INTERNAL) {
		reil_flag_spew_inst(esil, src->name + 1);
		src = reil_pop_arg(esil);
		ins->seq_num = esil->Reil->seq_num++;
	} else if (src_type == ARG_REG) {
		// No direct register to register transfer.
		ins->opcode = REIL_STR;
		ins->arg[0] = src;
		ins->arg[1] = R_NEW0(RAnalReilArg);
		ins->arg[2] = R_NEW0(RAnalReilArg);

		reil_make_arg(esil, ins->arg[1], " ");
		get_next_temp_reg(esil, tmp_buf);
		reil_make_arg(esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst(esil, ins);

		reil_push_arg(esil, ins->arg[2]);
		free(src);
		src = reil_pop_arg(esil);
		free(ins->arg[1]);
		free(ins->arg[2]);
	}

	// First, make a copy of the dst. We will need this to set the flags later on.
	dst_type = dst->type;
	if (src_type != ARG_ESIL_INTERNAL && dst_type == ARG_REG) {
		ins->opcode = REIL_STR;
		ins->arg[0] = dst;
		ins->arg[1] = R_NEW0(RAnalReilArg);
		ins->arg[2] = R_NEW0(RAnalReilArg);
		reil_make_arg(esil, ins->arg[1], " ");
		get_next_temp_reg(esil, tmp_buf);
		reil_make_arg(esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst(esil, ins);

		// Used for setting the flags
		snprintf(esil->Reil->old, sizeof(esil->Reil->old), "%s:%d",
				ins->arg[2]->name, ins->arg[2]->size);
		snprintf(esil->Reil->cur, sizeof(esil->Reil->cur), "%s:%d", dst->name,
				dst->size);
		esil->Reil->lastsz = dst->size;

		free(ins->arg[1]);
		free(ins->arg[2]);
	}

	// If we are modifying the Instruction Pointer, then we need to emit JCC instead.
	if (!strcmp(esil->Reil->pc, dst->name)) {
		ins->opcode = REIL_JCC;
		r_anal_esil_push (esil, "1:1");
		ins->arg[0] = reil_pop_arg (esil);
		ins->arg[1] = R_NEW0 (RAnalReilArg);
		reil_make_arg (esil, ins->arg[1], " ");
		ins->arg[2] = dst;
		reil_print_inst (esil, ins);

		free (ins->arg[1]);
		free (ins);
		return R_TRUE;
	}

	esil->Reil->seq_num = ins->seq_num;
	reil_cast_size(esil, src, dst);
	ins->seq_num = esil->Reil->seq_num;
	ins->opcode = REIL_STR;
	
	ins->arg[0] = reil_pop_arg(esil);
	if (!ins->arg[0]) return R_FALSE;

	ins->arg[2] = dst;
	ins->arg[1] = R_NEW0(RAnalReilArg);
	reil_make_arg(esil, ins->arg[1], " ");
	reil_print_inst(esil, ins);

	free (ins->arg[0]);
	free (dst);
	free (ins);

	return R_TRUE;
}

// General function for operations that take 2 operands
static int reil_binop(RAnalEsil *esil, RAnalReilOpcode opcode) {
	RAnalReilInst *ins;
	char tmp_buf[32];
	ut8 dst_size;
	RAnalReilArg *op2 = reil_pop_arg(esil);
	RAnalReilArg *op1 = reil_pop_arg(esil);

	if (!op1 || !op2) return R_FALSE;

	ins = reil_new_inst(esil);
	ins->opcode = opcode;
	ins->arg[0] = op2;
	ins->arg[1] = op1;
	ins->arg[2] = R_NEW0(RAnalReilArg);

	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);

	// Choose the larger of the two sizes as the size of dst
	dst_size = ins->arg[0]->size;
	if (dst_size < ins->arg[1]->size)
		dst_size = ins->arg[1]->size;

	// REIL_LT has a dst_size of 1.
	if (opcode == REIL_LT)
		dst_size = 1;

	ins->arg[2]->size = dst_size;
	reil_print_inst(esil, ins);

	reil_push_arg(esil, ins->arg[2]);

	free(op1);
	free(op2);
	free(ins->arg[2]);
	free(ins);
	return R_TRUE;
}

// General function for operations which re-assign to dst. Example, addeq.
static int reil_bineqop(RAnalEsil *esil, RAnalReilOpcode opcode) {
	int ret = 1;
	RAnalReilArg *op2 = reil_pop_arg(esil);
	if (!op2) return R_FALSE;

	reil_push_arg(esil, op2);
	ret &= reil_binop(esil, opcode);

	reil_push_arg(esil, op2);
	ret &= reil_eq(esil);

	free(op2);
	return ret;
}

static int reil_add(RAnalEsil *esil)     { return reil_binop (esil, REIL_ADD);   }
static int reil_addeq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_ADD); }
static int reil_mul(RAnalEsil *esil)     { return reil_binop (esil, REIL_MUL);   }
static int reil_muleq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_MUL); }
static int reil_sub(RAnalEsil *esil)     { return reil_binop (esil, REIL_SUB);   }
static int reil_subeq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_SUB); }
static int reil_div(RAnalEsil *esil)     { return reil_binop (esil, REIL_DIV);   }
static int reil_diveq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_DIV); }
static int reil_xor(RAnalEsil *esil)     { return reil_binop (esil, REIL_XOR);   }
static int reil_xoreq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_XOR); }
static int reil_and(RAnalEsil *esil)     { return reil_binop (esil, REIL_AND);   }
static int reil_andeq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_AND); }
static int reil_or(RAnalEsil *esil)      { return reil_binop (esil, REIL_OR);    }
static int reil_oreq(RAnalEsil *esil)    { return reil_bineqop (esil, REIL_OR);  }
static int reil_lsl(RAnalEsil *esil)     { return reil_binop (esil, REIL_SHL);   }
static int reil_lsleq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_SHL); }
static int reil_lsr(RAnalEsil *esil)     { return reil_binop (esil, REIL_SHR);   }
static int reil_lsreq(RAnalEsil *esil)   { return reil_bineqop (esil, REIL_SHR); }
static int reil_smaller(RAnalEsil *esil) { return reil_binop (esil, REIL_LT);    }

static int reil_cmp(RAnalEsil *esil) {
	RAnalReilInst *ins;
	char tmp_buf[32];
	RAnalReilArg *op2 = reil_pop_arg(esil);
	RAnalReilArg *op1 = reil_pop_arg(esil);

	if (!op1 || !op2) return R_FALSE;

	ins = reil_new_inst(esil);
	ins->opcode = REIL_EQ;
	ins->arg[0] = op2;
	ins->arg[1] = op1;
	ins->arg[2] = R_NEW0(RAnalReilArg);
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = 1;
	reil_print_inst(esil, ins);

	snprintf(esil->Reil->cur, sizeof(esil->Reil->old), "%s:%d",
			ins->arg[2]->name, ins->arg[2]->size);
	snprintf(esil->Reil->old, sizeof(esil->Reil->cur), "%s:%d", op2->name,
			op2->size);

	if (r_reg_get(esil->anal->reg, op2->name, -1)) {
		esil->Reil->lastsz = op2->size;
	} else if (r_reg_get(esil->anal->reg, op1->name, -1)) {
		esil->Reil->lastsz = op1->size;
	}

	reil_push_arg(esil, ins->arg[2]);

	free(op1);
	free(op2);
	free(ins->arg[2]);
	free(ins);
	return R_TRUE;
}

static int reil_smaller_equal(RAnalEsil *esil) {
	RAnalReilArg *op2 = reil_pop_arg(esil);
	RAnalReilArg *op1 = reil_pop_arg(esil);

	if (!op1 || !op2) return R_FALSE;

	reil_push_arg(esil, op1);
	reil_push_arg(esil, op2);

	reil_smaller(esil);

	reil_push_arg(esil, op1);
	reil_push_arg(esil, op2);

	reil_cmp(esil);
	reil_or(esil);

	free(op1);
	free(op2);
	return R_TRUE;
}

static int reil_larger(RAnalEsil *esil) {
	RAnalReilArg *op2 = reil_pop_arg(esil);
	RAnalReilArg *op1 = reil_pop_arg(esil);

	if (!op1 || !op2) return R_FALSE;

	reil_push_arg(esil, op2);
	reil_push_arg(esil, op1);

	reil_smaller(esil);

	free(op1);
	free(op2);
	return R_TRUE;
}

static int reil_larger_equal(RAnalEsil *esil) {
	RAnalReilArg *op2 = reil_pop_arg(esil);
	RAnalReilArg *op1 = reil_pop_arg(esil);

	if (!op1 || !op2) return R_FALSE;

	reil_push_arg(esil, op2);
	reil_push_arg(esil, op1);

	reil_smaller_equal(esil);

	free(op1);
	free(op2);
	return R_TRUE;
}

static int reil_dec(RAnalEsil *esil) {
	RAnalReilArg *op = reil_pop_arg(esil);
	
	if (!op) return R_FALSE;

	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op);
	reil_sub(esil);

	free(op);
	return R_TRUE;
}

static int reil_deceq(RAnalEsil *esil) {
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) return R_FALSE;

	reil_push_arg(esil, op1);
	reil_dec(esil);

	reil_push_arg(esil, op1);
	reil_eq(esil);

	free(op1);
	return R_TRUE;
}

static int reil_inc(RAnalEsil *esil) {
	RAnalReilArg *op = reil_pop_arg(esil);
	
	if (!op) return R_FALSE;

	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op);
	reil_add(esil);

	free(op);
	return R_TRUE;
}

static int reil_inceq(RAnalEsil *esil) {
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) return R_FALSE;

	reil_push_arg(esil, op1);
	reil_inc(esil);

	reil_push_arg(esil, op1);
	reil_eq(esil);

	return R_TRUE;
}

static int reil_neg(RAnalEsil *esil) {
	RAnalReilArg *op1 = reil_pop_arg(esil);
	RAnalReilInst *ins;
	char tmp_buf[32];
	if (!op1) return R_FALSE;

	ins = reil_new_inst (esil);
	ins->opcode = REIL_EQ;
	ins->arg[0] = op1;
	r_anal_esil_pushnum (esil, 0);
	ins->arg[1] = reil_pop_arg(esil);
	ins->arg[2] = R_NEW0 (RAnalReilArg);
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);

	if (ins->arg[0]->size < ins->arg[1]->size)
		ins->arg[1]->size = ins->arg[0]->size;

	ins->arg[2]->size = 1;

	reil_print_inst (esil, ins);
	reil_push_arg (esil, ins->arg[2]);

	free (op1);
	free (ins->arg[2]);
	free (ins->arg[1]);
	free (ins);
	return R_TRUE;
}

static int reil_negeq(RAnalEsil *esil) {
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) return R_FALSE;

	reil_push_arg (esil, op1);
	reil_neg (esil);
	reil_push_arg (esil, op1);
	reil_eq (esil);

	free (op1);
	return R_TRUE;
}

static int reil_not(RAnalEsil *esil) {
	RAnalReilInst *ins;
	char tmp_buf[32];
	RAnalReilArg *op1 = reil_pop_arg(esil);

	if (!op1) return R_FALSE;

	ins = reil_new_inst(esil);

	ins->opcode = REIL_NOT;
	ins->arg[0] = op1;
	ins->arg[1] = R_NEW0(RAnalReilArg);
	ins->arg[2] = R_NEW0(RAnalReilArg);

	reil_make_arg(esil, ins->arg[1], " ");
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = ins->arg[0]->size;
	reil_print_inst(esil, ins);

	reil_push_arg(esil, ins->arg[2]);

	free(op1);
	free(ins->arg[1]);
	free(ins->arg[2]);
	free(ins);
	return R_TRUE;
}

static int reil_if(RAnalEsil *esil) {
	RAnalReilInst *ins;
	RAnalReilArg *op1, *op2;
	op2 = reil_pop_arg(esil);
	op1 = reil_pop_arg(esil);

	if (!op1 || !op2) return R_FALSE;

	ins = reil_new_inst(esil);

	ins->opcode = REIL_JCC;
	ins->arg[0] = op1;
	ins->arg[2] = op2;
	ins->arg[1] = R_NEW0(RAnalReilArg);
	reil_make_arg(esil, ins->arg[1], " ");
	reil_print_inst(esil, ins);

	free(op1);
	free(op2);
	free(ins->arg[1]);
	free(ins);
	return R_TRUE;
}

static int reil_if_end(RAnalEsil *esil) { return R_TRUE; }

static int reil_peek(RAnalEsil *esil) {
	RAnalReilInst *ins;
	char tmp_buf[32];
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) return R_FALSE;

	ins = reil_new_inst(esil);

	ins->opcode = REIL_LDM;
	ins->arg[0] = op1;
	ins->arg[1] = R_NEW0(RAnalReilArg);
	ins->arg[2] = R_NEW0(RAnalReilArg);
	reil_make_arg(esil, ins->arg[1], " ");
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = ins->arg[0]->size;
	reil_print_inst(esil, ins);

	reil_push_arg(esil, ins->arg[2]);

	free(op1);
	free(ins->arg[1]);
	free(ins->arg[2]);
	free(ins);
	return R_TRUE;
}

// n = 8, 4, 2, 1
static int reil_peekn(RAnalEsil *esil, ut8 n) {
	RAnalReilArg *op1 = reil_pop_arg(esil);
	RAnalReilArg *op2;

	if (!op1) return R_FALSE;

	reil_push_arg(esil, op1);
	reil_peek(esil);

	// No need to cast if n = 0
	if (n == 0)
		return R_TRUE;

	op1 = reil_pop_arg(esil);
	if (!op1) return R_FALSE;

	op2 = R_NEW0(RAnalReilArg);
	op2->size = n * 8;
	op2->type = ARG_TEMP;
	get_next_temp_reg(esil, op2->name);

	esil->Reil->seq_num++;
	reil_cast_size(esil, op1, op2);

	esil->Reil->lastsz = 8 * n;

	free (op2);
	free (op1);

	return R_TRUE;
}

static int reil_peek1(RAnalEsil *esil) { return reil_peekn(esil, 1); }
static int reil_peek2(RAnalEsil *esil) { return reil_peekn(esil, 2); }
static int reil_peek4(RAnalEsil *esil) { return reil_peekn(esil, 4); }
static int reil_peek8(RAnalEsil *esil) { return reil_peekn(esil, 8); }

// n = 8, 4, 2, 1
static int reil_poken(RAnalEsil *esil, ut8 n) {
	RAnalReilArg *op2 = reil_pop_arg(esil);
	RAnalReilArg *op1 = reil_pop_arg(esil);
	RAnalReilInst *ins;
	char tmp_buf[32];

	if (!op1 || !op2) return R_FALSE;

	ins = reil_new_inst(esil);

	if (op1->type != ARG_ESIL_INTERNAL) {
		ins->opcode = REIL_LDM;
		ins->arg[0] = op2;
		ins->arg[1] = R_NEW0(RAnalReilArg);
		ins->arg[2] = R_NEW0(RAnalReilArg);

		reil_make_arg(esil, ins->arg[1], " ");
		get_next_temp_reg(esil, tmp_buf);
		reil_make_arg(esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst(esil, ins);

		snprintf(esil->Reil->old, sizeof(esil->Reil->old), "%s:%d",
				ins->arg[2]->name, ins->arg[2]->size);
		snprintf(esil->Reil->cur, sizeof(esil->Reil->cur), "%s:%d", op2->name,
				op2->size);
		esil->lastsz = n * 8;

		free(ins->arg[1]);
		free(ins->arg[2]);
	} else {
		reil_flag_spew_inst(esil, op1->name + 1);

		free(op1);

		op1 = reil_pop_arg(esil);
		ins->seq_num = esil->Reil->seq_num++;
	}

	ins->opcode = REIL_STM;
	ins->arg[0] = op1;
	ins->arg[2] = op2;
	ins->arg[1] = R_NEW0(RAnalReilArg);
	reil_make_arg(esil, ins->arg[1], " ");
	reil_print_inst(esil, ins);

	free(ins->arg[1]);
	free(op1);
	free(op2);
	free(ins);
	return R_TRUE;
}

static int reil_poke(RAnalEsil *esil) {
	return reil_poken(esil, esil->anal->bits / 8);
}

static int reil_poke1(RAnalEsil *esil) { return reil_poken(esil, 1); }
static int reil_poke2(RAnalEsil *esil) { return reil_poken(esil, 2); }
static int reil_poke4(RAnalEsil *esil) { return reil_poken(esil, 4); }
static int reil_poke8(RAnalEsil *esil) { return reil_poken(esil, 8); }

// Generic function to handle all mem_*eq_n functions. Example, mem_oreq_n
static int reil_mem_bineq_n(RAnalEsil *esil, RAnalReilOpcode opcode, ut8 size) {
	int ret = 1;
	RAnalReilArg *op2 = reil_pop_arg(esil);
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1 || !op2) return R_FALSE;

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

static int reil_mem_oreq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_OR, esil->anal->bits / 8); }
static int reil_mem_oreq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 1); }
static int reil_mem_oreq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 2); }
static int reil_mem_oreq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 4); }
static int reil_mem_oreq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 8); }

static int reil_mem_andeq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_AND, esil->anal->bits / 8); }
static int reil_mem_andeq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 1); }
static int reil_mem_andeq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 2); }
static int reil_mem_andeq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 4); }
static int reil_mem_andeq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 8); }

static int reil_mem_xoreq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_XOR, esil->anal->bits / 8); }
static int reil_mem_xoreq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 1); }
static int reil_mem_xoreq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 2); }
static int reil_mem_xoreq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 4); }
static int reil_mem_xoreq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 8); }

static int reil_mem_addeq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_ADD, esil->anal->bits / 8); }
static int reil_mem_addeq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 1); }
static int reil_mem_addeq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 2); }
static int reil_mem_addeq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 4); }
static int reil_mem_addeq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 8); }

static int reil_mem_subeq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_SUB, esil->anal->bits / 8); }
static int reil_mem_subeq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 1); }
static int reil_mem_subeq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 2); }
static int reil_mem_subeq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 4); }
static int reil_mem_subeq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 8); }

static int reil_mem_muleq(RAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_MUL, esil->anal->bits / 8); }
static int reil_mem_muleq1(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 1); }
static int reil_mem_muleq2(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 2); }
static int reil_mem_muleq4(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 4); }
static int reil_mem_muleq8(RAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 8); }

static int reil_mem_inceq_n(RAnalEsil *esil, ut8 size) {
	int ret = 1;
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) return R_FALSE;

	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op1);
	ret &= reil_mem_addeq_n(esil, size);

	free (op1);
	return ret;
}

static int reil_mem_inceq(RAnalEsil *esil) {
	return reil_mem_inceq_n(esil, esil->anal->bits / 8);
}
static int reil_mem_inceq1(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 1); }
static int reil_mem_inceq2(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 2); }
static int reil_mem_inceq4(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 4); }
static int reil_mem_inceq8(RAnalEsil *esil) { return reil_mem_inceq_n(esil, 8); }

static int reil_mem_deceq_n(RAnalEsil *esil, ut8 size) {
	int ret = 1;
	RAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) return R_FALSE;

	r_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op1);
	ret &= reil_mem_subeq_n(esil, size);

	free (op1);
	return ret;
}

static int reil_mem_deceq(RAnalEsil *esil) {
	return reil_mem_deceq_n(esil, esil->anal->bits / 8);
}
static int reil_mem_deceq1(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 1); }
static int reil_mem_deceq2(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 2); }
static int reil_mem_deceq4(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 4); }
static int reil_mem_deceq8(RAnalEsil *esil) { return reil_mem_deceq_n(esil, 8); }

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
	if (!esil || !esil->Reil->lastsz || esil->Reil->lastsz == 0) {
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

	r_anal_esil_pushnum(esil, esil->Reil->lastsz - 1);
	reil_push_arg(esil, op);

	reil_lsr(esil);
	free (op);
}

void reil_generate_overflow_flag(RAnalEsil *esil) {
	if (!esil || (esil->Reil->lastsz < 2))
		r_anal_esil_pushnum(esil, 0);

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
	if (!esil) return R_FALSE;

	esil->debug = 1;
	esil->anal = anal;
	esil->trap = 0;
	esil->trap_code = 0;

	/* Set up a callback for hook_command */
	esil->cb.hook_command = setup_reil_ins;

	esil->Reil = R_NEW0(RAnalReil);
	esil->Reil->reilNextTemp = 0;
	esil->Reil->addr = -1;
	esil->Reil->seq_num = 0;
	esil->Reil->skip = 0;

	// Store the pc
	const char *name = r_reg_get_name (esil->anal->reg, r_reg_get_name_idx ("pc"));
	strncpy (esil->Reil->pc, name, sizeof(esil->Reil->pc));

	r_anal_esil_mem_ro(esil, romem);

	r_anal_esil_set_op(esil, "=", reil_eq);
	r_anal_esil_set_op(esil, "+", reil_add);
	r_anal_esil_set_op(esil, "+=", reil_addeq);
	r_anal_esil_set_op(esil, "-", reil_sub);
	r_anal_esil_set_op(esil, "-=", reil_subeq);
	r_anal_esil_set_op(esil, "*", reil_mul);
	r_anal_esil_set_op(esil, "*=", reil_muleq);
	r_anal_esil_set_op(esil, "/", reil_div);
	r_anal_esil_set_op(esil, "/=", reil_diveq);
	r_anal_esil_set_op(esil, "^", reil_xor);
	r_anal_esil_set_op(esil, "^=", reil_xoreq);
	r_anal_esil_set_op(esil, "|", reil_or);
	r_anal_esil_set_op(esil, "|=", reil_oreq);
	r_anal_esil_set_op(esil, "&", reil_and);
	r_anal_esil_set_op(esil, "&=", reil_andeq);
	r_anal_esil_set_op(esil, "<<", reil_lsl);
	r_anal_esil_set_op(esil, "<<=", reil_lsleq);
	r_anal_esil_set_op(esil, ">>", reil_lsr);
	r_anal_esil_set_op(esil, ">>=", reil_lsreq);
	r_anal_esil_set_op(esil, "++=", reil_inceq);
	r_anal_esil_set_op(esil, "++", reil_inc);
	r_anal_esil_set_op(esil, "--=", reil_deceq);
	r_anal_esil_set_op(esil, "--", reil_dec);
	r_anal_esil_set_op(esil, "!", reil_neg);
	r_anal_esil_set_op(esil, "!=", reil_negeq);
	r_anal_esil_set_op(esil, "==", reil_cmp);
	r_anal_esil_set_op(esil, "<", reil_smaller);
	r_anal_esil_set_op(esil, ">", reil_larger);
	r_anal_esil_set_op(esil, "<=", reil_smaller_equal);
	r_anal_esil_set_op(esil, ">=", reil_larger_equal);
	r_anal_esil_set_op(esil, "[]", reil_peek);
	r_anal_esil_set_op(esil, "=[]", reil_poke);
	r_anal_esil_set_op(esil, "|=[]", reil_mem_oreq);
	r_anal_esil_set_op(esil, "^=[]", reil_mem_xoreq);
	r_anal_esil_set_op(esil, "&=[]", reil_mem_andeq);
	r_anal_esil_set_op(esil, "+=[]", reil_mem_addeq);
	r_anal_esil_set_op(esil, "-=[]", reil_mem_subeq);
	r_anal_esil_set_op(esil, "*=[]", reil_mem_muleq);
	r_anal_esil_set_op(esil, "++=[]", reil_mem_inceq);
	r_anal_esil_set_op(esil, "--=[]", reil_mem_deceq);
	r_anal_esil_set_op(esil, "=[1]", reil_poke1);
	r_anal_esil_set_op(esil, "=[2]", reil_poke2);
	r_anal_esil_set_op(esil, "=[4]", reil_poke4);
	r_anal_esil_set_op(esil, "=[8]", reil_poke8);
	r_anal_esil_set_op(esil, "[1]", reil_peek1);
	r_anal_esil_set_op(esil, "[2]", reil_peek2);
	r_anal_esil_set_op(esil, "[4]", reil_peek4);
	r_anal_esil_set_op(esil, "[8]", reil_peek8);
	r_anal_esil_set_op(esil, "|=[1]", reil_mem_oreq1);
	r_anal_esil_set_op(esil, "|=[2]", reil_mem_oreq2);
	r_anal_esil_set_op(esil, "|=[4]", reil_mem_oreq4);
	r_anal_esil_set_op(esil, "|=[8]", reil_mem_oreq8);
	r_anal_esil_set_op(esil, "^=[1]", reil_mem_xoreq1);
	r_anal_esil_set_op(esil, "^=[2]", reil_mem_xoreq2);
	r_anal_esil_set_op(esil, "^=[4]", reil_mem_xoreq4);
	r_anal_esil_set_op(esil, "^=[8]", reil_mem_xoreq8);
	r_anal_esil_set_op(esil, "&=[1]", reil_mem_andeq1);
	r_anal_esil_set_op(esil, "&=[2]", reil_mem_andeq2);
	r_anal_esil_set_op(esil, "&=[4]", reil_mem_andeq4);
	r_anal_esil_set_op(esil, "&=[8]", reil_mem_andeq8);
	r_anal_esil_set_op(esil, "+=[1]", reil_mem_addeq1);
	r_anal_esil_set_op(esil, "+=[2]", reil_mem_addeq2);
	r_anal_esil_set_op(esil, "+=[4]", reil_mem_addeq4);
	r_anal_esil_set_op(esil, "+=[8]", reil_mem_addeq8);
	r_anal_esil_set_op(esil, "-=[1]", reil_mem_subeq1);
	r_anal_esil_set_op(esil, "-=[2]", reil_mem_subeq2);
	r_anal_esil_set_op(esil, "-=[4]", reil_mem_subeq4);
	r_anal_esil_set_op(esil, "-=[8]", reil_mem_subeq8);
	r_anal_esil_set_op(esil, "*=[1]", reil_mem_muleq1);
	r_anal_esil_set_op(esil, "*=[2]", reil_mem_muleq2);
	r_anal_esil_set_op(esil, "*=[4]", reil_mem_muleq4);
	r_anal_esil_set_op(esil, "*=[8]", reil_mem_muleq8);
	r_anal_esil_set_op(esil, "++=[1]", reil_mem_inceq1);
	r_anal_esil_set_op(esil, "++=[2]", reil_mem_inceq2);
	r_anal_esil_set_op(esil, "++=[4]", reil_mem_inceq4);
	r_anal_esil_set_op(esil, "++=[8]", reil_mem_inceq8);
	r_anal_esil_set_op(esil, "--=[1]", reil_mem_deceq1);
	r_anal_esil_set_op(esil, "--=[2]", reil_mem_deceq2);
	r_anal_esil_set_op(esil, "--=[4]", reil_mem_deceq4);
	r_anal_esil_set_op(esil, "--=[8]", reil_mem_deceq8);
	r_anal_esil_set_op(esil, "?{", reil_if);
	r_anal_esil_set_op(esil, "}", reil_if_end);

	if (anal->cur && anal->cur->esil_init && anal->cur->esil_fini)
		return anal->cur->esil_init(esil);

	return R_TRUE;
}
