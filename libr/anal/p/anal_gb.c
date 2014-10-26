/* radare - LGPL - Copyright 2012 - pancake<nopcode.org>
			     2014 - condret

	this file was based on anal_i8080.c */

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_reg.h>
#define GB_DIS_LEN_ONLY
#include "../../asm/arch/gb/gbdis.c"
#include "../arch/gb/meta_gb_cmt.c"
#include <gb_makros.h>
#include <gb.h>

static const char *regs_1[] = { "Z", "N", "H", "C"};
static const char *regs_8[] = { "b", "c", "d", "e", "h", "l", "a", "a"};				//deprecate this and rename regs_x
static const char *regs_x[] = { "b", "c", "d", "e", "h", "l", "hl", "a"};
static const char *regs_16[] = { "bc", "de", "hl", "sp"};
static const char *regs_16_alt[] = { "bc", "de", "hl", "af" };

static ut8 gb_op_calljump(RAnal *a, RAnalOp *op, const ut8 *data, ut64 addr)
{
	if (GB_IS_RAM_DST (data[1],data[2])) {
		op->jump = GB_SOFTCAST (data[1], data[2]);
		r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "--> unpredictable");
		return R_FALSE;
	}
	if (!GB_IS_VBANK_DST (data[1], data[2]))
		op->jump = GB_SOFTCAST(data[1], data[2]);
	else	op->jump = GB_IB_DST (data[1], data[2], addr);
	return R_TRUE;
}

#if	0
static inline int gb_anal_esil_banksw (RAnalOp *op)							//remove that
{
	ut64 base = op->dst->base;
	if (op->addr < 0x4000 && 0x1fff < base && base < 0x4000) {
		r_strbuf_set (&op->esil, "mbcrom=0,?a%0x20,mbcrom=a-1");				//if a is a multiple of 0x20 mbcrom is 0, else it gets its value from a
		return R_TRUE;
	}
	if (base < 0x6000 && 0x3fff < base) {
		r_strbuf_set (&op->esil, "mbcram=a");
		return R_TRUE;
	}
	return R_FALSE;
}
#endif

static void gb_anal_esil_call (RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "2,sp,-=,%d,pc,+,sp,=[2],%"PFMT64d",pc,=", op->size, (op->jump & 0xffff));
}

static inline void gb_anal_esil_ccall (RAnalOp *op, const ut8 data)
{
	char cond;
	switch (data) {
		case 0xc4:
		case 0xcc:
			cond = 'Z';
			break;
		default:
			cond = 'C';
	}
	if (op->cond == R_ANAL_COND_EQ)
		r_strbuf_setf (&op->esil, "%c,?{,2,sp,-=,3,pc,+,sp,=[2],%"PFMT64d",pc,=,}", cond, (op->jump & 0xffff));
	else	r_strbuf_setf (&op->esil, "%c,!,?{,2,sp,-=,3,pc,+,sp,=[2],%"PFMT64d",pc,=,}", cond, (op->jump & 0xffff));
}

static inline void gb_anal_esil_ret (RAnalOp *op)
{
	r_strbuf_append (&op->esil, "sp,[2],pc,=,2,sp,+=");
}

static inline void gb_anal_esil_cret (RAnalOp *op, const ut8 data)
{
	char cond;
	if ((data & 0xd0) == 0xd0)
		cond = 'C';
	else	cond = 'Z';
	if (op->cond == R_ANAL_COND_EQ)
		r_strbuf_setf (&op->esil, "%c,?{,sp,[2],pc,=,2,sp,+=,}", cond);
	else	r_strbuf_setf (&op->esil, "%c,!,?{,sp,[2],pc,=,2,sp,+=,}", cond);
}

static inline void gb_anal_esil_cjmp (RAnalOp *op, const ut8 data)
{
	char cond;
	switch (data) {
		case 0x20:
		case 0x28:
		case 0xc2:
		case 0xca:
			cond = 'Z';
			break;
		default:
			cond = 'C';
	}
	if (op->cond == R_ANAL_COND_EQ)
		r_strbuf_setf (&op->esil, "%c,?{,0x%"PFMT64x",pc,=,}", cond, (op->jump & 0xffff));
	else	r_strbuf_setf (&op->esil, "%c,!,?{,0x%"PFMT64x",pc,=,}", cond, (op->jump & 0xffff));
}

static inline void gb_anal_esil_jmp (RAnalOp *op)
{
	r_strbuf_setf (&op->esil, "0x%"PFMT64x",pc,=", (op->jump & 0xffff));
}

static inline void gb_anal_jmp_hl (RReg *reg, RAnalOp *op)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "pc", R_REG_TYPE_GPR);
	op->src[0]->reg = r_reg_get (reg, "hl", R_REG_TYPE_GPR);
	r_strbuf_set (&op->esil, "hl,pc,=");
}

static inline void gb_anal_id (RAnal *anal, RAnalOp *op, const ut8 data)				//inc + dec
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->src[0]->absolute = R_TRUE;
	if (data == 0x34 || data == 0x35) {
		op->dst->memref = 1;
		op->dst->reg = r_reg_get (anal->reg, "hl", R_REG_TYPE_GPR);
		if (op->type == R_ANAL_OP_TYPE_ADD)
			r_strbuf_set (&op->esil, "1,hl,[1],+,hl,=[1],%c3,H,=,%z,Z,=,0,N,=");
		else	r_strbuf_set (&op->esil, "1,hl,[1],-,hl,=[1],%b4,H,=,%z,Z,=,1,N,=");
	} else {
		if (!(data & (1<<2))) {
			op->dst->reg = r_reg_get (anal->reg, regs_16[data>>4], R_REG_TYPE_GPR);
			if (op->type == R_ANAL_OP_TYPE_ADD)
				r_strbuf_setf (&op->esil, "1,%s,+=", regs_16[data>>4]);
			else	r_strbuf_setf (&op->esil, "1,%s,-=", regs_16[data>>4]);
		} else {
			op->dst->reg = r_reg_get (anal->reg, regs_8[data>>3], R_REG_TYPE_GPR);
			if (op->type == R_ANAL_OP_TYPE_ADD)
				r_strbuf_setf (&op->esil, "1,%s,+=,%%c3,H,=,%%z,Z,=,0,N,=", regs_8[data>>3]);
			else	r_strbuf_setf (&op->esil, "1,%s,-=,%%b4,H,=,%%z,Z,=,1,N,=", regs_8[data>>3]);
		}
	}
}

static inline void gb_anal_add_hl (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "hl", R_REG_TYPE_GPR);
	op->src[0]->reg = r_reg_get (reg, regs_16[((data & 0xf0)>>4)], R_REG_TYPE_GPR);
	r_strbuf_setf (&op->esil, "%s,hl,+=,0,N,=", regs_16[((data & 0xf0)>>4)]);	//hl+=<reg>,N=0
}

static inline void gb_anal_add_sp (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "sp", R_REG_TYPE_GPR);
	op->src[0]->imm = (st8)data;
	if (data < 128)
		r_strbuf_setf (&op->esil, "-0x%02x,sp,-=", data);		//sp-=0x90
	else	r_strbuf_setf (&op->esil, "0x%02x,sp,+=", data - 128);		//sp+=0x90
	r_strbuf_append (&op->esil, ",0,Z,=,0,N,=");
}

static void gb_anal_mov_imm (RReg *reg, RAnalOp *op, const ut8 *data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	if (data[0] & 1) {
		op->dst->reg = r_reg_get (reg, regs_16[data[0]>>4], R_REG_TYPE_GPR);
		op->src[0]->imm = GB_SOFTCAST (data[1], data[2]);
		r_strbuf_setf (&op->esil, "0x%04x,%s,=", op->src[0]->imm, regs_16[data[0]>>4]);
	} else {
		op->dst->reg = r_reg_get (reg, regs_8[data[0]>>3], R_REG_TYPE_GPR);
		op->src[0]->imm = data[1];
		r_strbuf_setf (&op->esil, "0x%02x,%s,=", op->src[0]->imm, regs_8[data[0]>>3]);
	}
	op->src[0]->absolute = R_TRUE;
	op->val = op->src[0]->imm;
}

static inline void gb_anal_mov_sp_hl (RReg *reg, RAnalOp *op)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "sp", R_REG_TYPE_GPR);
	op->src[0]->reg = r_reg_get (reg, "hl", R_REG_TYPE_GPR);
	r_strbuf_set (&op->esil, "hl,sp,=");
}

static inline void gb_anal_mov_hl_sp (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[1] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, regs_16[2], R_REG_TYPE_GPR);
	op->src[0]->reg = r_reg_get (reg, regs_16[3], R_REG_TYPE_GPR);
	op->src[1]->imm = (st8)data;
	if (data < 128)
		r_strbuf_setf (&op->esil, "0x%02x,sp,-,hl,=", data);		//hl=sp-0x90
	else	r_strbuf_setf (&op->esil, "0x%02x,sp,+,hl,=", data - 128);	//hl=sp+0x90
	r_strbuf_append (&op->esil, ",0,Z,=,0,N,=");
}

static void gb_anal_mov_reg (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, regs_8[(data/8) - 8], R_REG_TYPE_GPR);
	op->src[0]->reg = r_reg_get (reg, regs_8[data & 7], R_REG_TYPE_GPR);
	r_strbuf_setf (&op->esil, "%s,%s,=", regs_8[data & 7], regs_8[(data/8) - 8]);
}

static inline void gb_anal_mov_ime (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "ime", R_REG_TYPE_GPR);
	op->src[0]->absolute = R_TRUE;
	op->src[0]->imm = (data != 0xf3);
	r_strbuf_setf (&op->esil, "%d,ime,=", (int)op->src[0]->imm);
	if (data == 0xd9)
		r_strbuf_append (&op->esil, ",");
}

static inline void gb_anal_mov_scf (RReg *reg, RAnalOp *op)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, regs_1[3], R_REG_TYPE_GPR);
	op->src[0]->imm = 1;
	r_strbuf_set (&op->esil, "1,C,=");
}

static inline void gb_anal_xor_cpl (RReg *reg, RAnalOp *op)			//cpl
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, regs_8[7], R_REG_TYPE_GPR);
	op->src[0]->imm = 0xff;
	r_strbuf_set (&op->esil, "0xff,a,^=,1,N,=,1,H,=");
}

static inline void gb_anal_xor_ccf (RReg *reg, RAnalOp *op)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, regs_1[3], R_REG_TYPE_GPR);
	op->src[0]->imm = 1;
	r_strbuf_set (&op->esil, "C,!=");
}

static inline void gb_anal_cond (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	if (data & 0x8) op->cond = R_ANAL_COND_EQ;
	else op->cond = R_ANAL_COND_NE;
	switch (data) {
		case 0x20:
		case 0x28:
		case 0xc0:
		case 0xc2:
		case 0xc4:
		case 0xc8:
		case 0xca:
		case 0xcc:
			op->dst->reg = r_reg_get (reg, regs_1[0], R_REG_TYPE_GPR);
			break;
		default:
			op->dst->reg = r_reg_get (reg, regs_1[3], R_REG_TYPE_GPR);
	}
}

static inline void gb_anal_pp (RReg *reg, RAnalOp *op, const ut8 data)		//push , pop
{
	RAnalValue *val = r_anal_value_new ();
	val->reg = r_reg_get (reg, regs_16_alt[(data>>4) - 12], R_REG_TYPE_GPR);
	if ((data & 0xf) == 1) {
		op->dst = val;
		r_strbuf_setf (&op->esil, "sp,[2],%s,=,2,sp,+=", regs_16_alt[(data>>4) - 12]);		//pop
	} else {
		op->src[0] = val;
		r_strbuf_setf (&op->esil, "2,sp,-=,%s,sp,=[2]", regs_16_alt[(data>>4) - 12]);		//push
	}
}

static inline void gb_anal_and_res (RAnal *anal, RAnalOp *op, const ut8 data)	//res
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = ((~(0x1 << ((data >> 3) & 7))) & 0xff);
	op->dst->memref = ((data & 7) == 6);
	op->dst->reg = r_reg_get (anal->reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if (op->dst->memref)
		r_strbuf_setf (&op->esil, "0x%02x,%s,[1],&,%s,=[1]", op->src[0]->imm, regs_x[data & 7], regs_x[data & 7]);
	else	r_strbuf_setf (&op->esil, "0x%02x,%s,&=", op->src[0]->imm, regs_x[data & 7]);
}

static inline void gb_anal_and_bit (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1<<((data>>3) & 7);
	op->dst->memref = ((data & 7) == 6);
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if (op->dst->memref)
		r_strbuf_setf (&op->esil, "%i,%s,[1],&,0,==,%%z,Z,=,0,N,=,1,H,=", op->src[0]->imm, regs_x[data & 7]);
	else	r_strbuf_setf (&op->esil, "%i,%s,&,0,==,%%z,Z,=,0,N,=,1,H,=", op->src[0]->imm, regs_x[data & 7]);
}

static inline void gb_anal_or_set (RAnal *anal, RAnalOp *op, const ut8 data)	//set
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = (data>>3) & 7;
	op->dst->memref = ((data & 7) == 6);
	op->dst->reg = r_reg_get (anal->reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if (op->dst->memref)
		r_strbuf_setf (&op->esil, "0x%02x,%s,[1],|,%s,=[1]", op->src[0]->imm, regs_x[data & 7], regs_x[data & 7], op->src[0]->imm);
	else	r_strbuf_setf (&op->esil, "0x%02x,%s,|=", op->src[0]->imm, regs_x[data & 7]);
}

static void gb_anal_xoaasc (RReg *reg, RAnalOp *op, const ut8 *data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "a", R_REG_TYPE_GPR);
	op->src[0]->reg = r_reg_get (reg, regs_x[data[0] & 7], R_REG_TYPE_GPR);
	op->src[0]->memref = ((data[0] & 7) == 6);
	switch (op->type) {
		case R_ANAL_OP_TYPE_XOR:
			if (op->src[0]->memref)
				r_strbuf_setf (&op->esil, "%s,[1],a,^=,%%z,Z,=,0,N,=,0,H,=,0,C,=", regs_x[data[0] & 7]);
			else	r_strbuf_setf (&op->esil, "%s,a,^=,%%z,Z,=,0,N,=,0,H,=,0,C,=", regs_x[data[0] & 7]);
		break;
		case R_ANAL_OP_TYPE_OR:
			if (op->src[0]->memref)
				r_strbuf_setf (&op->esil, "%s,[1],a,|=,%%z,Z,=,0,N,=,0,H,=,0,C,=", regs_x[data[0] &7]);
			else	r_strbuf_setf (&op->esil, "%s,a,|=,%%z,Z,=,0,N,=,0,H,=,0,C,=", regs_x[data[0] & 7]);
		break;
		case R_ANAL_OP_TYPE_AND:
			if (op->src[0]->memref)
				r_strbuf_setf (&op->esil, "%s,[1],a,&=,%%z,Z,=,0,N,=,1,H,=,0,C,=", regs_x[data[0] & 7]);
			else	r_strbuf_setf (&op->esil, "%s,a,&=,%%z,Z,=,0,N,=,1,H,=,0,C,=", regs_x[data[0] & 7]);
		break;
		case R_ANAL_OP_TYPE_ADD:
			if (op->src[0]->memref) {
				if (data[0] > 0x87) {
					op->src[1] = r_anal_value_new ();
					op->src[1]->reg = r_reg_get (reg, "C", R_REG_TYPE_GPR);
					r_strbuf_setf ( &op->esil, "C,%s,[1],+,a,+=,%%z,Z,=,%%c3,H,=,%%c7,C,=,0,N,=", regs_x[data[0] & 7]);
				} else {
					r_strbuf_setf (&op->esil, "%s,[1],a,+=,%%z,Z,=,%%c3,H,=,%%c7,C,=,0,N,=", regs_x[data[0] & 7]);
				}
			} else {
				if (data[0] > 0x87) {
					op->src[1] = r_anal_value_new ();
					op->src[1]->reg = r_reg_get (reg, "C", R_REG_TYPE_GPR);
					r_strbuf_setf (&op->esil, "C,%s,+,a,+=,%%z,Z,=,%%c3,H,=,%%c7,C,=,0,N,=", regs_x[data[0] & 7]);
				} else {
					r_strbuf_setf (&op->esil, "%s,a,+=,%%z,Z,=,%%c3,H,=,%%c7,C,=,0,N,=", regs_x[data[0] & 7]);
				}
			}
		break;
		case R_ANAL_OP_TYPE_SUB:
			if (op->src[0]->memref) {
				if (data[0] > 0x97) {
					op->src[1] = r_anal_value_new ();
					op->src[1]->reg = r_reg_get (reg, "C", R_REG_TYPE_GPR);
					r_strbuf_setf (&op->esil, "C,%s,[1],+,a,-=,%%z,Z,=,%%b4,H,=,%%b8,C,=,1,N,=", regs_x[data[0] & 7]);
				} else {
					r_strbuf_setf (&op->esil, "%s,[1],a,-=,%%z,Z,=,%%b4,H,=,%%b8,C,=,1,N,=", regs_x[data[0] & 7]);
				}
			} else {
				if (data[0] > 0x97) {
					op->src[1] = r_anal_value_new ();
					op->src[1]->reg = r_reg_get (reg, "C", R_REG_TYPE_GPR);
					r_strbuf_setf (&op->esil, "C,%s,+,a,-=,%%z,Z,=,%%b4,H,=,%%b8,C,=,1,N,=", regs_x[data[0] & 7]);
				} else {
					r_strbuf_setf (&op->esil, "%s,a,-=,%%z,Z,=,%%b4,H,=,%%b8,C,=,1,N,=", regs_x[data[0] & 7]);
				}
			}
		break;
		case R_ANAL_OP_TYPE_CMP:
			if (op->src[0]->memref)
				r_strbuf_setf (&op->esil, "%s,[1],a,==,%%z,Z,=,%%b4,H,=,%%b8,C,=,1,N,=", regs_x[data[0] & 7]);
			else	r_strbuf_setf (&op->esil, "%s,a,==,%%z,Z,=,%%b4,H,=,%%b8,C,=,1,N,=", regs_x[data[0] & 7]);
		break;
	}
}

static void gb_anal_xoaasc_imm (RReg *reg, RAnalOp *op, const ut8 *data)	//xor , or, and, add, adc, sub, sbc, cp
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "a", R_REG_TYPE_GPR);
	op->src[0]->absolute = R_TRUE;
	op->src[0]->imm = data[1];
	switch (op->type) {
		case R_ANAL_OP_TYPE_XOR:
			r_strbuf_setf (&op->esil, "0x%02x,a,^=,%%z,Z,=,0,N,=,0,H,=,0,C,=", data[1]);
		break;
		case R_ANAL_OP_TYPE_OR:
			r_strbuf_setf (&op->esil, "0x%02x,a,|=,%%z,Z,=,0,N,=,0,H,=,0,C,=", data[1]);
		break;
		case R_ANAL_OP_TYPE_AND:
			r_strbuf_setf (&op->esil, "0x%02x,a,&=,%%z,Z,=,0,N,=,1,H,=,0,C,=", data[1]);
		break;
		case R_ANAL_OP_TYPE_ADD:
			r_strbuf_setf (&op->esil, "0x%02x,", data[1]);
			if (data[0] == 0xce) {					//adc
				op->src[1] = r_anal_value_new ();
				op->src[1]->reg = r_reg_get (reg, "C", R_REG_TYPE_GPR);
				r_strbuf_append (&op->esil, "C,+,");
			}
			r_strbuf_append (&op->esil, "a,+=,%z,Z,=,%c3,H,=,%c7,C,=,0,N,=");
		break;
		case R_ANAL_OP_TYPE_SUB:
			r_strbuf_setf (&op->esil, "0x%02x,", data[1]);
			if (data[0] == 0xde) {					//sbc
				op->src[1] = r_anal_value_new ();
				op->src[1]->reg = r_reg_get (reg, "C", R_REG_TYPE_GPR);
				r_strbuf_append (&op->esil, "C,-,");
			}
			r_strbuf_append (&op->esil, "a,-=,%z,Z,=,%b4,H,=,%b8,C,=,1,N,=");
		break;
		case R_ANAL_OP_TYPE_CMP:
			r_strbuf_setf (&op->esil, "%d,a,==,%%z,Z,=,%%b4,H,=,%%b8,C,=,1,N,=", data[1]);
		break;
	}
}

static inline void gb_anal_load_hl (RReg *reg, RAnalOp *op, const ut8 data)	//load with [hl] as memref - What to do with ldd and ldi?
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->reg = r_reg_get (reg, "hl", R_REG_TYPE_GPR);
	op->src[0]->memref = 1;
	op->src[0]->absolute = R_TRUE;
	op->dst->reg = r_reg_get (reg, regs_8[((data & 0x38)>>3)], R_REG_TYPE_GPR);
	r_strbuf_setf (&op->esil, "hl,[1],%s,=", regs_8[((data & 0x38)>>3)]);
}

static inline void gb_anal_load (RReg *reg, RAnalOp *op, const ut8 *data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "a", R_REG_TYPE_GPR);
	op->src[0]->memref = 1;
	switch (data[0]) {
		case 0xf0:
			op->src[0]->base = 0xff00 + data[1];
			r_strbuf_setf (&op->esil, "0x%04x,[1],a,=", op->src[0]->base);
			break;
		case 0xf2:
			op->src[0]->base = 0xff00;
			op->src[0]->regdelta = r_reg_get (reg, "c", R_REG_TYPE_GPR);
			r_strbuf_set (&op->esil, "0xff00,c,+,[1],a,=");
			break;
		case 0xfa:
			op->src[0]->base = GB_SOFTCAST (data[1], data[2]);
			if (op->src[0]->base < 0x4000)
				op->ptr = op->src[0]->base;
			else {
				if (op->addr > 0x3fff && op->src[0]->base < 0x8000)
					op->ptr = op->src[0]->base + (op->addr & 0xffffffffffff0000);					//hack
			}
			r_strbuf_setf (&op->esil, "0x%04x,[1],a,=", op->src[0]->base);
			break;
		default:
			op->src[0]->reg = r_reg_get (reg, regs_16[(data[0] & 0xf0)>>4], R_REG_TYPE_GPR);
			r_strbuf_setf (&op->esil, "%s,[1],a,=", regs_16[(data[0] & 0xf0)>>4]);
	}
}

static inline void gb_anal_store_hl (RReg *reg, RAnalOp *op, const ut8 *data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->reg = r_reg_get (reg, "hl", R_REG_TYPE_GPR);
	op->dst->memref = 1;
	op->src[0]->absolute = R_TRUE;
	if (data[0] == 0x36) {
		op->src[0]->imm = data[1];
		r_strbuf_setf (&op->esil, "0x%02x,hl,=[1]", data[1]);
	} else {
		op->src[0]->reg = r_reg_get (reg, regs_8[((data[0] & 0x38)>>3)], R_REG_TYPE_GPR);
		r_strbuf_setf (&op->esil, "%s,hl,=[1]", regs_8[(data[0] & 0x38)>>3]);
	}
}

static void gb_anal_store (RReg *reg, RAnalOp *op, const ut8 *data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->dst->memref = 1;
	op->src[0]->reg = r_reg_get (reg, "a", R_REG_TYPE_GPR);
	switch (data[0]) {
		case 0x08:
			op->dst->memref = 2;
			op->dst->base = GB_SOFTCAST (data[1], data[2]);
			op->src[0]->reg = r_reg_get (reg, "sp", R_REG_TYPE_GPR);
			r_strbuf_setf (&op->esil, "sp,0x%04x,=[2]", op->dst->base);
			break;
		case 0xe0:
			op->dst->base = 0xff00 + data[1];
			r_strbuf_setf (&op->esil, "a,0x%04x,=[1]", op->dst->base);
			break;
		case 0xe2:
			op->dst->base = 0xff00;
			op->dst->regdelta = r_reg_get (reg, "c", R_REG_TYPE_GPR);
			r_strbuf_set (&op->esil, "a,0xff00,c,+,=[1]");
			break;
		case 0xea:
			op->dst->base = GB_SOFTCAST (data[1], data[2]);
			r_strbuf_setf (&op->esil, "a,0x%04x,=[1]", op->dst->base);
			break;
		default:
			op->dst->reg = r_reg_get (reg, regs_16[(data[0] & 0xf0)>>4], R_REG_TYPE_GPR);
			r_strbuf_setf (&op->esil , "a,%s,=[1]", regs_16[(data[0] & 0xf0)>>4]);
	}
}

static inline void gb_anal_cb_swap (RReg *reg, RAnalOp* op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 4;
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if ((data & 7) == 6) {
		op->dst->memref = 1;
		r_strbuf_setf (&op->esil, "4,%s,[1],>>,4,%s,[1],<<,|,%s,=[1],%%z,Z,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
	} else	r_strbuf_setf (&op->esil, "4,%s,>>,4,%s,<<,|,%s,=,%%z,Z,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
}

static inline void gb_anal_cb_rlc (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if ((data & 7) == 6) {
		op->dst->memref = 1;
		r_strbuf_setf (&op->esil, "7,%s,[1],>>,1,&,C,=,1,%s,[1],<<,C,|,%s,=[1],%%z,Z,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
	} else	r_strbuf_setf (&op->esil, "1,%s,<<=,%%c7,C,=,C,%s,|=,%%z,Z,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7]);
}

static inline void gb_anal_cb_rl (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if ((data & 7) == 6) {
		op->dst->memref = 1;
		r_strbuf_setf (&op->esil, "1,%s,<<,C,|,%s,=[1],%%c7,C,=,%%z,Z,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7]);
	} else	r_strbuf_setf (&op->esil, "1,%s,<<,C,|,%s,=,%%c7,C,=,%%z,Z,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7]);
}

static inline void gb_anal_cb_rrc (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->dst->reg = r_reg_get(reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if ((data &7) == 6) {
		op->dst->memref = 1;
		r_strbuf_setf (&op->esil, "1,%s,[1],&,C,=,1,%s,[1],>>,7,C,<<,|,%s,=[1],%%z,Z,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
	} else	r_strbuf_setf (&op->esil, "1,%s,&,C,=,1,%s,>>,7,C,<<,|,%s,=,%%z,Z,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
}

static inline void gb_anal_cb_rr (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	if ((data & 7) == 6) {
		op->dst->memref = 1;
		r_strbuf_setf (&op->esil, "1,%s,[1],&,H,=,1,%s,[1],>>,7,C,<<,|,%s,=[1],H,C,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
	} else	r_strbuf_setf (&op->esil, "1,%s,&,H,=,1,%s,>>,7,C,<<,|,%s,=,H,C,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);	//HACK
}

static inline void gb_anal_cb_sla (RReg *reg, RAnalOp *op, const ut8 data)								//sra+sla+srl in one function, like xoaasc
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	op->dst->memref = ((data & 7) == 6);
	if (op->dst->memref)
		r_strbuf_setf (&op->esil, "1,%s,[1],<<,%s,=[1],%%c7,C,=,%s,[1],%s,=[1],%%z,Z,=,0,H,=,0,N,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
	else	r_strbuf_setf (&op->esil, "1,%s,<<=,%%c7,C,=,%s,%s,=,%%z,Z,=,0,H,=0,N,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);	// %s,%s,= is a HACK for %%z
}

static inline void gb_anal_cb_sra (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	op->dst->memref = ((data & 7) == 6);
	if (op->dst->memref)
		r_strbuf_setf (&op->esil, "1,%s,[1],&,C,=,0x80,%s,[1],&,1,%s,[1],>>,|,%s,=[1],%%z,Z,=,0,N,=,0,H,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);	//spaguesil
	else	r_strbuf_setf (&op->esil, "1,%s,&,C,=,0x80,%s,&,1,%s,>>,|,%s=,%%z,Z,=,0,N,=,0,H,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
}

static inline void gb_anal_cb_srl (RReg *reg, RAnalOp *op, const ut8 data)
{
	op->dst = r_anal_value_new ();
	op->src[0] = r_anal_value_new ();
	op->src[0]->imm = 1;
	op->dst->reg = r_reg_get (reg, regs_x[data & 7], R_REG_TYPE_GPR);
	op->dst->memref = ((data & 7) == 6);
	if (op->dst->memref)
		r_strbuf_setf (&op->esil, "1,%s,[1],&,C,=,1,%s,[1],>>,%s,=[1],%%z,Z,=,0,N,=,0,H,=", regs_x[data & 7], regs_x[data & 7], regs_x[data & 7]);
	else	r_strbuf_setf (&op->esil, "1,%s,&,C,=,1,%s,>>=,%%z,Z,=,0,N,=,0,H,=", regs_x[data & 7], regs_x[data & 7]);
}

static int gb_custom_daa (RAnalEsil *esil)
{
	ut8 a, H, C, Z;
	if (!esil || !esil->anal || !esil->anal->reg)
		return R_FALSE;
	H = r_reg_getv (esil->anal->reg, "H");
	C = r_reg_getv (esil->anal->reg, "C");
	a = r_reg_getv (esil->anal->reg, "a");
	esil->old = a;
	if (r_reg_getv (esil->anal->reg, "N")) {
		if (C)
			a = (a - 0x60) & 0xff;
		else	r_reg_setv (esil->anal->reg, "C", 0);
		if (H)
			a = (a - 0x06) & 0xff;
	} else {
		if (C || (a > 0x99)) {
			a = (a + 0x60) & 0xff;
			r_reg_setv (esil->anal->reg, "C", 1);
		}
		if (H || ((a & 0x0f) > 0x09))
			a += 0x06;;
	}
	esil->cur = a;
	Z = (a == 0);
	r_reg_setv (esil->anal->reg, "a", a);
	r_reg_setv (esil->anal->reg, "Z", Z);
	r_reg_setv (esil->anal->reg, "H", 0);
	return R_TRUE;
}

static int gb_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len){
	int ilen = gbOpLength (gb_op[data[0]].type);
	if (ilen > len)
		ilen=0;
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = ilen;
	op->nopcode = 1;
	r_strbuf_init (&op->esil);
	switch (data[0])
	{
		case 0x00:
		case 0x40:
		case 0x49:
		case 0x52:
		case 0x5b:
		case 0x64:
		case 0x6d:
		case 0x7f:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case 0x01:
		case 0x11:
		case 0x21:
		case 0x31:
			gb_anal_mov_imm (anal->reg, op, data);
			op->cycles = 12;
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 0xf8:
			gb_anal_mov_hl_sp (anal->reg, op, data[1]);
			op->cycles = 12;
			op->type = R_ANAL_OP_TYPE_MOV;
			op->type2 = R_ANAL_OP_TYPE_ADD;
			break;
		case 0x06:
		case 0x0e:
		case 0x16:
		case 0x1e:
		case 0x26:
		case 0x2e:
		case 0x3e:
			gb_anal_mov_imm (anal->reg, op, data);
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 0xf9:
			gb_anal_mov_sp_hl (anal->reg, op);
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_MOV;		// LD
			break;
		case 0x03:
		case 0x13:
		case 0x23:
		case 0x33:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_ADD;
			gb_anal_id (anal, op, data[0]);
			break;
		case 0x04:
		case 0x0c:
		case 0x14:
		case 0x1c:
		case 0x24:
		case 0x2c:
		case 0x3c:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_ADD;		// INC
			gb_anal_id (anal, op, data[0]);
			break;
		case 0x34:
			op->cycles = 12;
			op->type = R_ANAL_OP_TYPE_ADD;
			gb_anal_id (anal, op, data[0]);
			break;
		case 0xea:
			meta_gb_bankswitch_cmt (anal, addr, GB_SOFTCAST (data[1], data[2]));
			gb_anal_store (anal->reg, op, data);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x08:
			meta_gb_bankswitch_cmt (anal, addr, GB_SOFTCAST (data[1], data[2]));
			gb_anal_store (anal->reg, op, data);
			op->cycles = 20;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x02:
		case 0x12:
		case 0xe2:
			gb_anal_store (anal->reg, op, data);
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x36:
		case 0x22:
		case 0x32:
		case 0x70:
		case 0x71:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
		case 0x77:
			gb_anal_store_hl (anal->reg, op, data);
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_STORE;	//LD
			break;
		case 0xe0:
			meta_gb_hardware_cmt (anal, data[1], addr);
			gb_anal_store (anal->reg, op, data);
			op->cycles = 12;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x47:
		case 0x48:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4f:
		case 0x50:
		case 0x51:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x57:
		case 0x58:
		case 0x59:
		case 0x5a:
		case 0x5c:
		case 0x5d:
		case 0x5f:
		case 0x60:
		case 0x61:
		case 0x62:
		case 0x63:
		case 0x65:
		case 0x67:
		case 0x68:
		case 0x69:
		case 0x6a:
		case 0x6b:
		case 0x6c:
		case 0x6f:
		case 0x78:
		case 0x79:
		case 0x7a:
		case 0x7b:
		case 0x7c:
		case 0x7d:
			gb_anal_mov_reg (anal->reg, op, data[0]);
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_MOV;		// LD
			break;
		case 0x0a:
		case 0x1a:
		case 0x2a:
		case 0x3a:
		case 0xf2:
			gb_anal_load (anal->reg, op, data);
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0x46:
		case 0x4e:
		case 0x56:
		case 0x5e:
		case 0x66:
		case 0x6e:
		case 0x7e:
			gb_anal_load_hl (anal->reg, op, data[0]);
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0xf0:
			gb_anal_load (anal->reg, op, data);
			meta_gb_hardware_cmt (anal, data[1], addr);
			op->cycles = 12;
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0xfa:
			gb_anal_load (anal->reg, op, data);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0x80:
		case 0x81:
		case 0x82:
		case 0x83:
		case 0x84:
		case 0x85:
		case 0x87:
		case 0x88:
		case 0x89:
		case 0x8a:
		case 0x8b:
		case 0x8c:
		case 0x8d:
		case 0x8f:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_ADD;
			gb_anal_xoaasc (anal->reg, op, data);
			break;
		case 0x09:
		case 0x19:
		case 0x29:
		case 0x39:
			gb_anal_add_hl (anal->reg, op, data[0]);
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 0x86:
		case 0x8e:
			op->type = R_ANAL_OP_TYPE_ADD;
			gb_anal_xoaasc (anal->reg, op, data);
			op->cycles = 8;
			break;
		case 0xc6:
		case 0xce:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_ADD;
			gb_anal_xoaasc_imm (anal->reg, op, data);
			break;
		case 0xe8:
			gb_anal_add_sp (anal->reg, op, data[1]);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 0x90:
		case 0x91:
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x97:
		case 0x98:
		case 0x99:
		case 0x9a:
		case 0x9b:
		case 0x9c:
		case 0x9d:
		case 0x9f:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_SUB;
			gb_anal_xoaasc (anal->reg, op, data);
			break;
		case 0x96:
		case 0x9e:
			op->type = R_ANAL_OP_TYPE_SUB;
			gb_anal_xoaasc (anal->reg, op, data);
			op->cycles = 8;
			break;
		case 0xd6:
		case 0xde:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_SUB;
			gb_anal_xoaasc_imm (anal->reg, op, data);
			break;
		case 0xa0:
		case 0xa1:
		case 0xa2:
		case 0xa3:
		case 0xa4:
		case 0xa5:
		case 0xa7:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_AND;
			gb_anal_xoaasc (anal->reg, op, data);
			break;
		case 0xe6:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_AND;
			gb_anal_xoaasc_imm (anal->reg, op, data);
			break;
		case 0xa6:
			op->type = R_ANAL_OP_TYPE_AND;
			gb_anal_xoaasc (anal->reg, op, data);
			op->cycles = 8;
			break;
		case 0x07:					//rlca
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_ROL;
			gb_anal_cb_rlc (anal->reg, op, 7);
			break;
		case 0x17:					//rla
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_ROL;
			gb_anal_cb_rl (anal->reg, op, 7);
			break;
		case 0x0f:					//rrca
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_ROR;
			gb_anal_cb_rrc (anal->reg, op, 7);
			break;
		case 0x1f:					//rra
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_ROR;
			gb_anal_cb_rr (anal->reg, op, 7);
			break;
		case 0x2f:
			gb_anal_xor_cpl (anal->reg, op);	//cpl
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0x3f:					//ccf
			gb_anal_xor_ccf (anal->reg, op);
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0xa8:
		case 0xa9:
		case 0xaa:
		case 0xab:
		case 0xac:
		case 0xad:
		case 0xaf:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_XOR;
			gb_anal_xoaasc (anal->reg, op, data);
			break;
		case 0xee:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_XOR;
			gb_anal_xoaasc_imm (anal->reg, op, data);
			break;
		case 0xae:
			op->type = R_ANAL_OP_TYPE_XOR;
			gb_anal_xoaasc (anal->reg, op, data);
			op->cycles = 8;
			break;
		case 0xb0:
		case 0xb1:
		case 0xb2:
		case 0xb3:
		case 0xb4:
		case 0xb5:
		case 0xb7:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_OR;
			gb_anal_xoaasc (anal->reg, op, data);
			break;
		case 0xf6:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_OR;
			gb_anal_xoaasc_imm (anal->reg, op, data);
			break;
		case 0xb6:
			op->type = R_ANAL_OP_TYPE_OR;
			gb_anal_xoaasc (anal->reg, op, data);
			op->cycles = 8;
			break;
		case 0xb8:
		case 0xb9:
		case 0xba:
		case 0xbb:
		case 0xbc:
		case 0xbd:
		case 0xbf:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_CMP;
			gb_anal_xoaasc (anal->reg, op, data);
			break;
		case 0xfe:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_CMP;
			gb_anal_xoaasc_imm (anal->reg, op, data);
			break;
		case 0xbe:
			op->type = R_ANAL_OP_TYPE_CMP;
			gb_anal_xoaasc (anal->reg, op, data);
			op->cycles = 8;
			break;
		case 0xc0:
		case 0xc8:
		case 0xd0:
		case 0xd8:
			gb_anal_cond (anal->reg, op, data[0]);
			gb_anal_esil_cret (op, data[0]);
			op->eob = 1;
			op->cycles = 20;
			op->failcycles = 8;
			op->type = R_ANAL_OP_TYPE_CRET;
			break;
		case 0xd9:
			gb_anal_mov_ime (anal->reg, op, data[0]);
			op->type2 = R_ANAL_OP_TYPE_MOV;
		case 0xc9:
			op->eob = 1;
			op->cycles = 16;
			gb_anal_esil_ret (op);
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -2;
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case 0x0b:
		case 0x1b:
		case 0x2b:
		case 0x3b:
			op->cycles = 8;
			op->type = R_ANAL_OP_TYPE_SUB;
			gb_anal_id (anal, op, data[0]);
			break;
		case 0x05:
		case 0x0d:
		case 0x15:
		case 0x1d:
		case 0x25:
		case 0x2d:
		case 0x3d:
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_SUB;		// DEC
			gb_anal_id (anal, op, data[0]);
			break;
		case 0x35:
			op->cycles = 12;
			op->type = R_ANAL_OP_TYPE_SUB;
			gb_anal_id (anal, op, data[0]);
			break;
		case 0xc5:
		case 0xd5:
		case 0xe5:
		case 0xf5:
			gb_anal_pp (anal->reg, op, data[0]);
			op->cycles = 16;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = 2;
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case 0xc1:
		case 0xd1:
		case 0xe1:
		case 0xf1:
			gb_anal_pp (anal->reg, op, data[0]);
			op->cycles = 12;
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -2;
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case 0xc3:
			if( gb_op_calljump (anal, op, data, addr)) {
				op->type = R_ANAL_OP_TYPE_JMP;
				gb_anal_esil_jmp (op);
			} else {
				op->type = R_ANAL_OP_TYPE_UJMP;
			}
			op->eob = 1;
			op->cycles = 16;
			op->fail = addr+ilen;
			break;
		case 0x18:					// JR
			op->jump = addr + ilen + (st8)data[1];
			op->fail = addr + ilen;
			gb_anal_esil_jmp (op);
			op->cycles = 12;
			op->eob = 1;
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case 0x20:
		case 0x28:
		case 0x30:
		case 0x38:					//JR cond
			gb_anal_cond (anal->reg, op, data[0]);
			op->jump = addr + ilen + (st8)data[1];
			op->fail = addr + ilen;
			gb_anal_esil_cjmp (op, data[0]);
			op->cycles = 12;
			op->failcycles = 8;
			op->eob = 1;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case 0xc2:
		case 0xca:
		case 0xd2:
		case 0xda:
			if( gb_op_calljump (anal, op, data, addr)) {
				op->type = R_ANAL_OP_TYPE_CJMP;
			} else {
				op->type = R_ANAL_OP_TYPE_UCJMP;
			}
			op->eob = 1;
			gb_anal_cond (anal->reg, op, data[0]);
			gb_anal_esil_cjmp (op, data[0]);
			op->cycles = 16;
			op->failcycles = 12;
			op->fail = addr+ilen;
			break;
		case 0xe9:
			op->cycles = 4;
			op->eob = 1;
			op->type = R_ANAL_OP_TYPE_UJMP;
			gb_anal_jmp_hl (anal->reg, op);
			break;
		case 0x76:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->eob = 1;			//halt migth wait for interrupts
			op->fail = addr + ilen;
			if(len > 1)
				op->jump = addr + gbOpLength (gb_op[data[1]].type) + ilen;
			break;
		case 0xcd:
			if ( gb_op_calljump (anal, op, data, addr))
				op->type = R_ANAL_OP_TYPE_CALL;
			else	op->type = R_ANAL_OP_TYPE_UCALL;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 24;
			break;
		case 0xc4:
		case 0xcc:
		case 0xd4:
		case 0xdc:
			gb_anal_cond (anal->reg, op, data[0]);
			if( gb_op_calljump (anal, op, data, addr))
				op->type = R_ANAL_OP_TYPE_CCALL;
			else	op->type = R_ANAL_OP_TYPE_UCCALL;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_ccall (op, data[0]);
			op->cycles = 24;
			op->failcycles = 12;
			break;
                case 0xc7:				//rst 0
			op->jump = 0x00;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0xcf:				//rst 8
                        op->jump = 0x08;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
                        break;
		case 0xd7:				//rst 16
			op->jump = 0x10;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0xdf:				//rst 24
			op->jump = 0x18;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0xe7:				//rst 32
			op->jump = 0x20;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0xef:				//rst 40
			op->jump = 0x28;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0xf7:				//rst 48
			op->jump = 0x30;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0xff:				//rst 56
			op->jump = 0x38;
			op->fail = addr + ilen;
			op->eob = 1;
			gb_anal_esil_call (op);
			op->cycles = 16;
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0xf3:				//di
		case 0xfb:				//ei
			gb_anal_mov_ime (anal->reg, op, data[0]);
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 0x37:
			gb_anal_mov_scf (anal->reg, op);
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 0x27:				//daa
			op->cycles = 4;
			op->type = R_ANAL_OP_TYPE_XOR;
			r_strbuf_set (&op->esil, "daa");
			break;
		case 0x10:				//stop
			op->type = R_ANAL_OP_TYPE_NULL;
			r_strbuf_set (&op->esil, "TODO,stop");
			break;
		case 0xcb:
			op->nopcode = 2;
			switch (data[1]>>3)
			{
				case 0:
					if ((data[1]&7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_ROL;
					gb_anal_cb_rlc (anal->reg, op, data[1]);
					break;
				case 1:
					if ((data[1] & 7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_ROR;
					gb_anal_cb_rrc (anal->reg, op, data[1]);
					break;
				case 2:
					if ((data[1]&7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_ROL;
					gb_anal_cb_rl (anal->reg, op, data[1]);
					break;
				case 3:
					if ((data[1]&7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_ROR;
					gb_anal_cb_rr (anal->reg, op, data[1]);
					break;
				case 4:
					if ((data [1] & 7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_SAL;
					gb_anal_cb_sla (anal->reg, op, data[1]);
					break;
				case 6:
					if ((data[1] & 7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_ROL;
					gb_anal_cb_swap (anal->reg, op, data[1]);
					break;
				case 5:
					if ((data [1] & 7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_SAR;
					gb_anal_cb_sra (anal->reg, op, data[1]);
					break;
				case 7:
					if ((data [1] & 7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_SHR;
					gb_anal_cb_srl (anal->reg, op, data[1]);
					break;
				case 8:
				case 9:
				case 10:
				case 11:
				case 12:
				case 13:
				case 14:
				case 15:
					if ((data[1]&7) == 6)
						op->cycles = 12;
					else	op->cycles = 8;
					op->type = R_ANAL_OP_TYPE_ACMP;
					gb_anal_and_bit (anal->reg, op, data[1]);
					break;			//bit
				case 16:
				case 17:
				case 18:
				case 19:
				case 20:
				case 21:
				case 22:
				case 23:
					if ((data[1]&7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					gb_anal_and_res (anal, op, data[1]);
					op->type = R_ANAL_OP_TYPE_AND;
					break;			//res
				case 24:
				case 25:
				case 26:
				case 27:
				case 28:
				case 29:
				case 30:
				case 31:
					if ((data[1]&7) == 6)
						op->cycles = 16;
					else	op->cycles = 8;
					gb_anal_or_set (anal, op, data[1]);
					op->type = R_ANAL_OP_TYPE_OR;
					break;			//set
			}
			r_strbuf_append (&op->esil, ",N=0,H=0");
	}
	if (op->type == R_ANAL_OP_TYPE_CALL)
	{
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
	}
	return op->size;
}

/*
	The reg-profile below does not represent the real gameboy registers.
		->There is no such thing like m, mpc or mbc. there is only pc.
	m and mbc should make it easier to inspect the current mbc-state, because
	the mbc can be seen as a register but it isn't. For the Gameboy the mbc is invisble.
*/

static int set_reg_profile(RAnal *anal) {
	const char *p = "=pc	mpc\n"
		"=sp	sp\n"
		"=a0	af\n"
		"=a1	bc\n"
		"=a2	de\n"
		"=a3	hl\n"

		"gpr	mpc	.32	0	0\n"
		"gpr	pc	.16	0	0\n"
		"gpr	m	.16	2	0\n"

		"gpr	sp	.16	4	0\n"

		"gpr	af	.16	6	0\n"
		"gpr	f	.8	6	0\n"
		"gpr	a	.8	7	0\n"
		"gpr	Z	.1	.55	0\n"
		"gpr	N	.1	.54	0\n"
		"gpr	H	.1	.53	0\n"
		"gpr	C	.1	.52	0\n"

		"gpr	bc	.16	8	0\n"
		"gpr	c	.8	8	0\n"
		"gpr	b	.8	9	0\n"

		"gpr	de	.16	10	0\n"
		"gpr	e	.8	10	0\n"
		"gpr	d	.8	11	0\n"

		"gpr	hl	.16	12	0\n"
		"gpr	l	.8	12	0\n"
		"gpr	h	.8	13	0\n"

		"gpr	mbcrom	.16	14	0\n"
		"gpr	mbcram	.16	16	0\n"

		"gpr	ime	.1	18	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

static int esil_gb_init (RAnalEsil *esil)
{
	GBUser *user = R_NEW0 (GBUser);
	r_anal_esil_set_op (esil, "daa", gb_custom_daa);
	if (user) {
		if (esil->anal) {
			esil->anal->iob.read_at (esil->anal->iob.io, 0x147, &user->mbc_id, 1);
			esil->anal->iob.read_at (esil->anal->iob.io, 0x148, &user->romsz_id, 1);
			esil->anal->iob.read_at (esil->anal->iob.io, 0x149, &user->ramsz_id, 1);
		}
		esil->user = user;
	}
	return R_TRUE;
}

static int esil_gb_fini (RAnalEsil *esil)
{
	R_FREE (esil->user);
	return R_TRUE;
}

struct r_anal_plugin_t r_anal_plugin_gb = {
	.name = "gb",
	.desc = "Gameboy CPU code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_NONE,
	.esil = R_TRUE,
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.op = &gb_anop,
	.set_reg_profile = &set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL,
	.esil_init = esil_gb_init,
	.esil_fini = esil_gb_fini
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_gb
};
#endif
