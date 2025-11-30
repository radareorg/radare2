/* radare - LGPL - Copyright 2012-2025 - pancake, condret */

#include <r_arch.h>
#include "./gbdis.c"
#include "./gbasm.c"
#include "./gb_makros.h"
#include "./meta_gb_cmt.c"
#include "./gb_makros.h"
#include "./gb.h"

static const char * const regs_1[] = { "Z", "N", "H", "C" };
static const char * const regs_8[] = { "b", "c", "d", "e", "h", "l", "hl", "a" };
static const char * const regs_16[] = { "bc", "de", "hl", "sp" };
static const char * const regs_16_alt[] = { "bc", "de", "hl", "af" };

static ut8 gb_op_calljump(RArchSession *a, RAnalOp *op, const ut8 *data, ut64 addr) {
	if (GB_IS_RAM_DST (data[1],data[2])) {
		op->jump = GB_SOFTCAST (data[1], data[2]);
		// XXX r_meta_set_string (a, R_META_TYPE_COMMENT, addr, "--> unpredictable");
		return false;
	}
	if (!GB_IS_VBANK_DST (data[1], data[2])) {
		op->jump = GB_SOFTCAST (data[1], data[2]);
	} else {
		op->jump = GB_IB_DST (data[1], data[2], addr);
	}
	return true;
}

#if 0
static inline int gb_anal_esil_banksw(RAnalOp *op) {
	ut64 base = op->dst->base;
	if (op->addr < 0x4000 && 0x1fff < base && base < 0x4000) {
		r_strbuf_set (&op->esil, "mbcrom=0,?a%0x20,mbcrom=a-1"); //if a is a multiple of 0x20 mbcrom is 0, else it gets its value from a
		return true;
	}
	if (base < 0x6000 && 0x3fff < base) {
		r_strbuf_set (&op->esil, "mbcram=a");
		return true;
	}
	return false;
}
#endif

static void gb_anal_esil_call(RAnalOp *op) {
	r_strbuf_setf (&op->esil, "2,sp,-=,pc,sp,=[2],%"PFMT64d",pc,:=", (op->jump & 0xffff));
}

static inline void gb_anal_esil_ccall(RAnalOp *op, const ut8 data) {
	char cond;
	switch (data) {
	case 0xc4:
	case 0xcc:
		cond = 'Z';
		break;
	default:
		cond = 'C';
		break;
	}
	if (op->cond == R_ANAL_CONDTYPE_EQ) {
		r_strbuf_setf (&op->esil, "%c,?{,2,sp,-=,pc,sp,=[2],%"PFMT64d",pc,:=,}", cond, (op->jump & 0xffff));
	} else {
		r_strbuf_setf (&op->esil, "%c,!,?{,2,sp,-=,pc,sp,=[2],%" PFMT64d ",pc,:=,}", cond, (op->jump & 0xffff));
	}
}

static inline void gb_anal_esil_ret(RAnalOp *op) {
	r_strbuf_append (&op->esil, "sp,[2],pc,:=,2,sp,+=");
}

static inline void gb_anal_esil_cret(RAnalOp *op, const ut8 data) {
	char cond;
	if ((data & 0xd0) == 0xd0) {
		cond = 'C';
	} else {
		cond = 'Z';
	}
	if (op->cond == R_ANAL_CONDTYPE_EQ) {
		r_strbuf_setf (&op->esil, "%c,?{,sp,[2],pc,:=,2,sp,+=,}", cond);
	} else {
		r_strbuf_setf (&op->esil, "%c,!,?{,sp,[2],pc,:=,2,sp,+=,}", cond);
	}
}

static inline void gb_anal_esil_cjmp(RAnalOp *op, const ut8 data) {
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
	if (op->cond == R_ANAL_CONDTYPE_EQ) {
		r_strbuf_setf (&op->esil, "%c,?{,0x%"PFMT64x",pc,:=,}", cond, (op->jump & 0xffff));
	} else {
		r_strbuf_setf (&op->esil, "%c,!,?{,0x%"PFMT64x",pc,:=,}", cond, (op->jump & 0xffff));
	}
}

static inline void gb_anal_esil_jmp(RAnalOp *op) {
	r_strbuf_setf (&op->esil, "0x%"PFMT64x",pc,:=", (op->jump & 0xffff));
}

static inline void gb_anal_jmp_hl(RAnalOp *op) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "pc";
	src->reg = "hl";
	r_strbuf_set (&op->esil, "hl,pc,:=");
}

static inline void gb_anal_id(RArchSession *as, RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	src->absolute = true;
	if (data == 0x34 || data == 0x35) {
		dst->memref = 1;
		dst->reg = "hl";
		if (op->type == R_ANAL_OP_TYPE_ADD) {
			r_strbuf_set (&op->esil, "1,hl,[1],+,hl,=[1],3,$c,H,:=,$z,Z,:=,0,N,:=");
		} else {
			r_strbuf_set (&op->esil, "1,hl,[1],-,hl,=[1],4,$b,H,:=,$z,Z,:=,1,N,:=");
		}
	} else {
		if (!(data & (1<<2))) {
			dst->reg = regs_16[data>>4];
			if (op->type == R_ANAL_OP_TYPE_ADD) {
				r_strbuf_setf (&op->esil, "1,%s,+=", regs_16[data>>4]);
			} else {
				r_strbuf_setf (&op->esil, "1,%s,-=", regs_16[data >> 4]);
			}
		} else {
			dst->reg = regs_8[data>>3];
			if (op->type == R_ANAL_OP_TYPE_ADD) {
				r_strbuf_setf (&op->esil, "1,%s,+=,3,$c,H,:=,$z,Z,:=,0,N,:=", regs_8[data>>3]);
			} else {
				r_strbuf_setf (&op->esil, "1,%s,-=,4,$b,H,:=,$z,Z,:=,1,N,:=", regs_8[data >> 3]);
			}
		}
	}
}

static inline void gb_anal_add_hl(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "hl";
	src->reg = regs_16[((data & 0xf0)>>4)];
	r_strbuf_setf (&op->esil, "%s,hl,+=,0,N,:=", regs_16[((data & 0xf0)>>4)]);	//hl+=<reg>,N=0
}

static inline void gb_anal_add_sp(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "sp";
	src->imm = (st8)data;
	if (data < 128) {
		r_strbuf_setf (&op->esil, "0x%02x,sp,+=", data);
	} else {
		r_strbuf_setf (&op->esil, "0x%02x,sp,-=", 0 - (st8)data);
	}
	r_strbuf_append (&op->esil, ",0,Z,=,0,N,:=");
}

static void gb_anal_mov_imm(RAnalOp *op, const ut8 *data) {
	RAnalValue *dst = RVecRArchValue_emplace_back (&op->dsts);
	RAnalValue *src = RVecRArchValue_emplace_back (&op->srcs);
	if (data[0] & 1) {
		dst->reg = regs_16[data[0]>>4];
		dst->type = R_ANAL_VAL_REG;
		src->imm = GB_SOFTCAST (data[1], data[2]);
		src->type = R_ANAL_VAL_IMM;
		r_strbuf_setf (&op->esil, "0x%04" PFMT64x ",%s,=", src->imm, regs_16[data[0]>>4]);
	} else {
		dst->reg = regs_8[data[0]>>3];
		dst->type = R_ANAL_VAL_REG;
		src->imm = data[1];
		src->type = R_ANAL_VAL_IMM;
		r_strbuf_setf (&op->esil, "0x%02" PFMT64x ",%s,=", src->imm, regs_8[data[0]>>3]);
	}
	src->absolute = true;
	op->val = src->imm;
}

static inline void gb_anal_mov_sp_hl(RAnalOp *op) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "sp";
	src->reg = "hl";
	r_strbuf_set (&op->esil, "hl,sp,=");
}

static inline void gb_anal_mov_hl_sp(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src0, *src1;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src0 = RVecRArchValue_emplace_back (&op->srcs);
	src1 = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = regs_16[2];
	src0->reg = regs_16[3];
	src1->imm = (st8)data;
	src1->type = R_ANAL_VAL_IMM;
	if (data < 128) {
		r_strbuf_setf (&op->esil, "0x%02x,sp,+,hl,=", data);
	} else {
		r_strbuf_setf (&op->esil, "0x%02x,sp,-,hl,=", 0 - (st8)data);
	}
	r_strbuf_append (&op->esil, ",0,Z,=,0,N,:=");
}

static void gb_anal_mov_reg(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = regs_8[(data/8) - 8];
	src->reg = regs_8[data & 7];
	r_strbuf_setf (&op->esil, "%s,%s,=", regs_8[data & 7], regs_8[(data/8) - 8]);
}

static inline void gb_anal_mov_ime(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "ime";
	src->absolute = true;
	src->imm = (data != 0xf3);
	r_strbuf_setf (&op->esil, "%d,ime,=", (int)src->imm);
	if (data == 0xd9) {
		r_strbuf_append (&op->esil, ",");
	}
}

static inline void gb_anal_mov_scf(RAnalOp *op) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = regs_1[3];
	src->imm = 1;
	r_strbuf_set (&op->esil, "1,C,:=");
}

static inline void gb_anal_xor_cpl(RAnalOp *op) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = regs_8[7];
	src->imm = 0xff;
	r_strbuf_set (&op->esil, "0xff,a,^=,1,N,:=,1,H,:=");
}

static inline void gb_anal_xor_ccf(RAnalOp *op) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = regs_1[3];
	src->imm = 1;
	r_strbuf_set (&op->esil, "C,!=");
}

static inline void gb_anal_cond(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	if (data & 0x8) {
		op->cond = R_ANAL_CONDTYPE_EQ;
	} else {
		op->cond = R_ANAL_CONDTYPE_NE;
	}
	switch (data) {
	case 0x20:
	case 0x28:
	case 0xc0:
	case 0xc2:
	case 0xc4:
	case 0xc8:
	case 0xca:
	case 0xcc:
		dst->reg = regs_1[0];
		break;
	default:
		dst->reg = regs_1[3];
	}
}

static inline void gb_anal_pp(RAnalOp *op, const ut8 data) {//push , pop
	RAnalValue val = {0};
	val.reg = regs_16_alt[(data>>4) - 12];
	if ((data & 0xf) == 1) {
		RVecRArchValue_push_back (&op->dsts, &val);
		r_strbuf_setf (&op->esil, "sp,[2],%s,=,2,sp,+=", regs_16_alt[(data>>4) - 12]);		//pop
	} else {
		RVecRArchValue_push_back (&op->srcs, &val);
		r_strbuf_setf (&op->esil, "2,sp,-=,%s,sp,=[2]", regs_16_alt[(data>>4) - 12]);		//push
	}
}

static inline void gb_anal_and_res(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = ((~(0x1 << ((data >> 3) & 7))) & 0xff);
	dst->memref = ((data & 7) == 6);
	dst->reg = regs_8[data & 7];
	if (dst->memref) {
		r_strbuf_setf (&op->esil, "0x%02" PFMT64x ",%s,[1],&,%s,=[1]", src->imm, regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "0x%02" PFMT64x ",%s,&=", src->imm, regs_8[data & 7]);
	}
}

static inline void gb_anal_and_bit(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1<<((data>>3) & 7);
	dst->memref = ((data & 7) == 6);
	dst->reg = regs_8[data & 7];
	if (dst->memref) {
		r_strbuf_setf (&op->esil, "%" PFMT64d ",%s,[1],&,0,==,$z,Z,:=,0,N,:=,1,H,:=", src->imm, regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "%" PFMT64d ",%s,&,0,==,$z,Z,:=,0,N,:=,1,H,:=", src->imm, regs_8[data & 7]);
	}
}

static inline void gb_anal_or_set(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = (data>>3) & 7;
	dst->memref = ((data & 7) == 6);
	dst->reg = regs_8[data & 7];
	if (dst->memref) {
		r_strbuf_setf (&op->esil, "0x%02" PFMT64x ",%s,[1],|,%s,=[1]", src->imm, regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "0x%02" PFMT64x ",%s,|=", src->imm, regs_8[data & 7]);
	}
}

static void gb_anal_xoaasc(RAnalOp *op, const ut8 *data) {
	RAnalValue *dst, *src0, *src1;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src0 = RVecRArchValue_emplace_back (&op->srcs);
	src1 = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "a";
	src0->reg = regs_8[data[0] & 7];
	src0->memref = ((data[0] & 7) == 6);
	switch (op->type) {
	case R_ANAL_OP_TYPE_XOR:
		if (src0->memref) {
			r_strbuf_setf (&op->esil, "%s,[1],a,^=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", regs_8[data[0] & 7]);
		} else {
			r_strbuf_setf (&op->esil, "%s,a,^=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", regs_8[data[0] & 7]);
		}
		break;
	case R_ANAL_OP_TYPE_OR:
		if (src0->memref) {
			r_strbuf_setf (&op->esil, "%s,[1],a,|=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", regs_8[data[0] &7]);
		} else {
			r_strbuf_setf (&op->esil, "%s,a,|=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", regs_8[data[0] & 7]);
		}
		break;
	case R_ANAL_OP_TYPE_AND:
		if (src0->memref) {
			r_strbuf_setf (&op->esil, "%s,[1],a,&=,$z,Z,:=,0,N,:=,1,H,:=,0,C,:=", regs_8[data[0] & 7]);
		} else {
			r_strbuf_setf (&op->esil, "%s,a,&=,$z,Z,:=,0,N,:=,1,H,:=,0,C,:=", regs_8[data[0] & 7]);
		}
		break;
	case R_ANAL_OP_TYPE_ADD:
		if (src0->memref) {
			if (data[0] > 0x87) {
				src1->reg = "C";
				r_strbuf_setf (&op->esil, "C,%s,[1],+,a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", regs_8[data[0] & 7]);
			} else {
				r_strbuf_setf (&op->esil, "%s,[1],a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", regs_8[data[0] & 7]);
			}
		} else {
			if (data[0] > 0x87) {
				src1->reg = "C";
				r_strbuf_setf (&op->esil, "C,%s,+,a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", regs_8[data[0] & 7]);
			} else {
				r_strbuf_setf (&op->esil, "%s,a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", regs_8[data[0] & 7]);
			}
		}
		break;
	case R_ANAL_OP_TYPE_SUB:
		if (src0->memref) {
			if (data[0] > 0x97) {
				src1->reg = "C";
				r_strbuf_setf (&op->esil, "C,%s,[1],+,a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", regs_8[data[0] & 7]);
			} else {
				r_strbuf_setf (&op->esil, "%s,[1],a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", regs_8[data[0] & 7]);
			}
		} else {
			if (data[0] > 0x97) {
				src1->reg = "C";
				r_strbuf_setf (&op->esil, "C,%s,+,a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", regs_8[data[0] & 7]);
			} else {
				r_strbuf_setf (&op->esil, "%s,a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", regs_8[data[0] & 7]);
			}
		}
		break;
	case R_ANAL_OP_TYPE_CMP:
		if (src0->memref) {
			r_strbuf_setf (&op->esil, "%s,[1],a,==,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", regs_8[data[0] & 7]);
		} else {
			r_strbuf_setf (&op->esil, "%s,a,==,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", regs_8[data[0] & 7]);
		}
		break;
	default:
		// not handled yet
		break;
	}
}

// xor , or, and, add, adc, sub, sbc, cp
static void gb_anal_xoaasc_imm(RAnalOp *op, const ut8 *data) {
	RAnalValue *dst, *src0, *src1;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src0 = RVecRArchValue_emplace_back (&op->srcs);
	src1 = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "a";
	src0->absolute = true;
	src0->imm = data[1];
	src0->type = R_ANAL_VAL_IMM;
	switch (op->type) {
	case R_ANAL_OP_TYPE_XOR:
		r_strbuf_setf (&op->esil, "0x%02x,a,^=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", data[1]);
		break;
	case R_ANAL_OP_TYPE_OR:
		r_strbuf_setf (&op->esil, "0x%02x,a,|=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", data[1]);
		break;
	case R_ANAL_OP_TYPE_AND:
		r_strbuf_setf (&op->esil, "0x%02x,a,&=,$z,Z,:=,0,N,:=,1,H,:=,0,C,:=", data[1]);
		break;
	case R_ANAL_OP_TYPE_ADD:
		r_strbuf_setf (&op->esil, "0x%02x,", data[1]);
		if (data[0] == 0xce) {					//adc
			src1->reg = "C";
			r_strbuf_append (&op->esil, "a,+=,C,NUM,7,$c,C,:=,3,$c,H,:=,a,+=,7,$c,C,|,C,:=,3,$c,H,|=,a,a,=,$z,Z,:=,0,N,:=");
		} else {
			r_strbuf_append (&op->esil, "a,+=,3,$c,H,:=,7,$c,C,:=,0,N,:=,a,a,=,$z,Z,:=");
		}
		break;
	case R_ANAL_OP_TYPE_SUB:
		r_strbuf_setf (&op->esil, "0x%02x,", data[1]);
		if (data[0] == 0xde) {					//sbc
			src1->reg = "C";
			r_strbuf_append (&op->esil, "a,-=,C,NUM,8,$b,C,:=,4,$b,H,:=,a,-=,8,$b,C,|,C,=,4,$b,H,|,H,=,a,a,=,$z,Z,:=,1,N,:=");
		} else {
			r_strbuf_append (&op->esil, "a,-=,4,$b,H,:=,8,$b,C,:=,1,N,:=,a,a,=,$z,Z,:=");
		}
		break;
	case R_ANAL_OP_TYPE_CMP:
		r_strbuf_setf (&op->esil, "%d,a,==,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", data[1]);
		break;
	}
}

// load with [hl] as memref
static inline void gb_anal_load_hl(RAnalOp *op, const ut8 data) {
	RAnalValue *dst = RVecRArchValue_emplace_back (&op->dsts);
	RAnalValue *src = RVecRArchValue_emplace_back (&op->srcs);
	src->reg = "hl";
	src->memref = 1;
	src->absolute = true;
	dst->reg = regs_8[((data & 0x38) >> 3)];
	r_strbuf_setf (&op->esil, "hl,[1],%s,=", regs_8[((data & 0x38)>>3)]);
	if (data == 0x3a) {
		r_strbuf_append (&op->esil, ",1,hl,-=");
	}
	if (data == 0x2a) {
		r_strbuf_set (&op->esil, "hl,[1],a,=,1,hl,+=");			//hack in concept
	}
}

static inline void gb_anal_load(RAnalOp *op, const ut8 *data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "a";
	src->memref = 1;
	switch (data[0]) {
	case 0xf0:
		src->base = 0xff00 + data[1];
		r_strbuf_setf (&op->esil, "0x%04" PFMT64x ",[1],a,=", src->base);
		break;
	case 0xf2:
		src->base = 0xff00;
		src->regdelta = "c";
		r_strbuf_set (&op->esil, "0xff00,c,+,[1],a,=");
		break;
	case 0xfa:
		src->base = GB_SOFTCAST (data[1], data[2]);
		if (src->base < 0x4000) {
			op->ptr = src->base;
		} else {
			if (op->addr > 0x3fff && src->base < 0x8000) { /* hack */
				op->ptr = src->base + (op->addr & 0xffffffffffff0000LL);
			}
		}
		r_strbuf_setf (&op->esil, "0x%04" PFMT64x ",[1],a,=", src->base);
		break;
	default:
		src->reg = regs_16[(data[0] & 0xf0) >> 4];
		r_strbuf_setf (&op->esil, "%s,[1],a,=", regs_16[(data[0] & 0xf0) >> 4]);
		break;
	}
}

static inline void gb_anal_store_hl(RAnalOp *op, const ut8 *data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->reg = "hl";
	dst->memref = 1;
	src->absolute = true;
	if (data[0] == 0x36) {
		src->imm = data[1];
		r_strbuf_setf (&op->esil, "0x%02x,hl,=[1]", data[1]);
	} else {
		src->reg = regs_8[data[0] & 0x07];
		r_strbuf_setf (&op->esil, "%s,hl,=[1]", regs_8[data[0] & 0x07]);
	}
	if (data[0] == 0x32) {
		r_strbuf_set (&op->esil, "a,hl,=[1],1,hl,-=");
	}
	if (data[0] == 0x22) {
		r_strbuf_set (&op->esil, "a,hl,=[1],1,hl,+=");
	}
}

static void gb_anal_store(RAnalOp *op, const ut8 *data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	dst->memref = 1;
	src->reg = "a";
	switch (data[0]) {
		case 0x08:
			dst->memref = 2;
			dst->base = GB_SOFTCAST (data[1], data[2]);
			src->reg = "sp";
			r_strbuf_setf (&op->esil, "sp,0x%04" PFMT64x ",=[2]", dst->base);
			break;
		case 0xe0:
			dst->base = 0xff00 + data[1];
			r_strbuf_setf (&op->esil, "a,0x%04" PFMT64x ",=[1]", dst->base);
			break;
		case 0xe2:
			dst->base = 0xff00;
			dst->regdelta = "c";
			r_strbuf_set (&op->esil, "a,0xff00,c,+,=[1]");
			break;
		case 0xea:
			dst->base = GB_SOFTCAST (data[1], data[2]);
			r_strbuf_setf (&op->esil, "a,0x%04" PFMT64x ",=[1]", dst->base);
			break;
		default:
			dst->reg = regs_16[(data[0] & 0xf0)>>4];
			r_strbuf_setf (&op->esil , "a,%s,=[1]", regs_16[(data[0] & 0xf0)>>4]);
	}
}

static inline void gb_anal_cb_swap(RAnalOp* op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 4;
	dst->reg = regs_8[data & 7];
	if ((data & 7) == 6) {
		dst->memref = 1;
		r_strbuf_setf (&op->esil, "4,%s,[1],>>,4,%s,[1],<<,|,%s,=[1],$z,Z,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "4,%s,>>,4,%s,<<,|,%s,=,$z,Z,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	}
}

static inline void gb_anal_cb_rlc(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	dst->reg = regs_8[data & 7];
	if ((data & 7) == 6) {
		dst->memref = 1;
		r_strbuf_setf (&op->esil, "7,%s,[1],>>,1,&,C,:=,1,%s,[1],<<,C,|,%s,=[1],$z,Z,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "1,%s,<<=,7,$c,C,:=,C,%s,|=,$z,Z,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7]);
	}
}

static inline void gb_anal_cb_rl(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	dst->reg = regs_8[data & 7];
	if ((data & 7) == 6) {
		dst->memref = 1;
		r_strbuf_setf (&op->esil, "1,%s,<<,C,|,%s,=[1],7,$c,C,:=,$z,Z,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "1,%s,<<,C,|,%s,=,7,$c,C,:=,$z,Z,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7]);
	}
}

static inline void gb_anal_cb_rrc(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	dst->reg = regs_8[data & 7];
	if ((data &7) == 6) {
		dst->memref = 1;
		r_strbuf_setf (&op->esil, "1,%s,[1],&,C,:=,1,%s,[1],>>,7,C,<<,|,%s,=[1],$z,Z,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "1,%s,&,C,:=,1,%s,>>,7,C,<<,|,%s,=,$z,Z,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	}
}

static inline void gb_anal_cb_rr(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	dst->reg = regs_8[data & 7];
	if ((data & 7) == 6) {
		dst->memref = 1;
		r_strbuf_setf (&op->esil, "1,%s,[1],&,H,:=,1,%s,[1],>>,7,C,<<,|,%s,=[1],H,C,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "1,%s,&,H,:=,1,%s,>>,7,C,<<,|,%s,=,H,C,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]); //HACK
	}
}

static inline void gb_anal_cb_sla(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	//sra+sla+srl in one function, like xoaasc
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	dst->reg = regs_8[data & 7];
	dst->memref = ((data & 7) == 6);
	if (dst->memref) {
		r_strbuf_setf (&op->esil, "1,%s,[1],<<,%s,=[1],7,$c,C,:=,%s,[1],%s,=[1],$z,Z,:=,0,H,:=,0,N,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "1,%s,<<=,7,$c,C,:=,%s,%s,=,$z,Z,:=,0,H,:=0,N,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]); // %s,%s,= is a HACK for $z
	}
}

static inline void gb_anal_cb_sra(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	dst->reg = regs_8[data & 7];
	dst->memref = ((data & 7) == 6);
	if (dst->memref) {
		r_strbuf_setf (&op->esil, "1,%s,[1],&,C,:=,0x80,%s,[1],&,1,%s,[1],>>,|,%s,=[1],$z,Z,:=,0,N,:=,0,H,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);	//spaguesil
	} else {
		r_strbuf_setf (&op->esil, "1,%s,&,C,:=,0x80,%s,&,1,%s,>>,|,%s,=,$z,Z,:=,0,N,:=,0,H,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	}
}

static inline void gb_anal_cb_srl(RAnalOp *op, const ut8 data) {
	RAnalValue *dst, *src;
	dst = RVecRArchValue_emplace_back (&op->dsts);
	src = RVecRArchValue_emplace_back (&op->srcs);
	src->imm = 1;
	dst->reg = regs_8[data & 7];
	dst->memref = ((data & 7) == 6);
	if (dst->memref) {
		r_strbuf_setf (&op->esil, "1,%s,[1],&,C,:=,1,%s,[1],>>,%s,=[1],$z,Z,:=,0,N,:=,0,H,:=", regs_8[data & 7], regs_8[data & 7], regs_8[data & 7]);
	} else {
		r_strbuf_setf (&op->esil, "1,%s,&,C,:=,1,%s,>>=,$z,Z,:=,0,N,:=,0,H,:=", regs_8[data & 7], regs_8[data & 7]);
	}
}

static bool gb_custom_daa(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	char *v = r_esil_pop (esil);
	ut64 n;
	if (!v || !r_esil_get_parm (esil, v, &n)) {
		return false;
	}
	R_FREE (v);
	ut8 val = (ut8)n;
	if (R_UNLIKELY (!r_esil_reg_read (esil, "H", &n, NULL))) {
		return false;
	}
	const ut8 H = (ut8)n;
	if (R_UNLIKELY (!r_esil_reg_read (esil, "C", &n, NULL))) {
		return false;
	}
	const ut8 C = (ut8)n;
	if (R_UNLIKELY (!r_esil_reg_read (esil, "N", &n, NULL))) {
		return false;
	}
	if (n) {
		if (C) {
			val = (val - 0x60) & 0xff;
		}
		if (H) {
			val = (val - 0x06) & 0xff;
		}
		return r_esil_pushnum (esil, val);
	}
	if (C || (val > 0x99)) {
		val = (val + 0x60) & 0xff;
	}
	if (H || ((val & 0x0f) > 0x09)) {
		val += 0x06;
	}
	return r_esil_pushnum (esil, val);
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *data = op->bytes;
	const int len = op->size;
	const int ilen = gbOpLength (gb_op[data[0]].type);
	if (ilen > len) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 0;
		return false;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		gbDisass (op, data);
	}
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = ilen;
	op->nopcode = 1;
	switch (data[0]) {
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
		gb_anal_mov_imm (op, data);
		op->cycles = 12;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0xf8:
		gb_anal_mov_hl_sp (op, data[1]);
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
		gb_anal_mov_imm (op, data);
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0xf9:
		gb_anal_mov_sp_hl (op);
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_MOV;		// LD
		break;
	case 0x03:
	case 0x13:
	case 0x23:
	case 0x33:
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_ADD;
		gb_anal_id (as, op, data[0]);
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
		gb_anal_id (as, op, data[0]);
		break;
	case 0x34:
		op->cycles = 12;
		op->type = R_ANAL_OP_TYPE_ADD;
		gb_anal_id (as, op, data[0]);
		break;
	case 0xea:
		meta_gb_bankswitch_cmt (as, addr, GB_SOFTCAST (data[1], data[2]));
		gb_anal_store (op, data);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case 0x08:
		meta_gb_bankswitch_cmt (as, addr, GB_SOFTCAST (data[1], data[2]));
		gb_anal_store (op, data);
		op->cycles = 20;
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case 0x02:
	case 0x12:
	case 0xe2:
		gb_anal_store (op, data);
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
		gb_anal_store_hl (op, data);
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_STORE;	//LD
		break;
	case 0xe0:
		gb_anal_store (op, data);
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
		gb_anal_mov_reg (op, data[0]);
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_MOV;		// LD
		break;
	case 0x0a:
	case 0x1a:
	case 0xf2:
		gb_anal_load (op, data);
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x2a:
	case 0x3a:
	case 0x46:
	case 0x4e:
	case 0x56:
	case 0x5e:
	case 0x66:
	case 0x6e:
	case 0x7e:
		gb_anal_load_hl (op, data[0]);
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0xf0:
		gb_anal_load (op, data);
		op->cycles = 12;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0xfa:
		gb_anal_load (op, data);
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
		gb_anal_xoaasc (op, data);
		break;
	case 0x09:
	case 0x19:
	case 0x29:
	case 0x39:
		gb_anal_add_hl (op, data[0]);
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x86:
	case 0x8e:
		op->type = R_ANAL_OP_TYPE_ADD;
		gb_anal_xoaasc (op, data);
		op->cycles = 8;
		break;
	case 0xc6:
	case 0xce:
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_ADD;
		gb_anal_xoaasc_imm (op, data);
		break;
	case 0xe8:
		gb_anal_add_sp (op, data[1]);
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
		gb_anal_xoaasc (op, data);
		break;
	case 0x96:
	case 0x9e:
		op->type = R_ANAL_OP_TYPE_SUB;
		gb_anal_xoaasc (op, data);
		op->cycles = 8;
		break;
	case 0xd6:
	case 0xde:
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_SUB;
		gb_anal_xoaasc_imm (op, data);
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
		gb_anal_xoaasc (op, data);
		break;
	case 0xe6:
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_AND;
		gb_anal_xoaasc_imm (op, data);
		break;
	case 0xa6:
		op->type = R_ANAL_OP_TYPE_AND;
		gb_anal_xoaasc (op, data);
		op->cycles = 8;
		break;
	case 0x07:					//rlca
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_ROL;
		gb_anal_cb_rlc (op, 7);
		break;
	case 0x17:					//rla
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_ROL;
		gb_anal_cb_rl (op, 7);
		break;
	case 0x0f:					//rrca
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_ROR;
		gb_anal_cb_rrc (op, 7);
		break;
	case 0x1f:					//rra
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_ROR;
		gb_anal_cb_rr (op, 7);
		break;
	case 0x2f:
		gb_anal_xor_cpl (op);	//cpl
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x3f:					//ccf
		gb_anal_xor_ccf (op);
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
		gb_anal_xoaasc (op, data);
		break;
	case 0xee:
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_XOR;
		gb_anal_xoaasc_imm (op, data);
		break;
	case 0xae:
		op->type = R_ANAL_OP_TYPE_XOR;
		gb_anal_xoaasc (op, data);
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
		gb_anal_xoaasc (op, data);
		break;
	case 0xf6:
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_OR;
		gb_anal_xoaasc_imm (op, data);
		break;
	case 0xb6:
		op->type = R_ANAL_OP_TYPE_OR;
		gb_anal_xoaasc (op, data);
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
		gb_anal_xoaasc (op, data);
		break;
	case 0xfe:
		op->cycles = 8;
		op->type = R_ANAL_OP_TYPE_CMP;
		gb_anal_xoaasc_imm (op, data);
		break;
	case 0xbe:
		op->type = R_ANAL_OP_TYPE_CMP;
		gb_anal_xoaasc (op, data);
		op->cycles = 8;
		break;
	case 0xc0:
	case 0xc8:
	case 0xd0:
	case 0xd8:
		gb_anal_cond (op, data[0]);
		gb_anal_esil_cret (op, data[0]);
		op->eob = true;
		op->cycles = 20;
		op->failcycles = 8;
		op->type = R_ANAL_OP_TYPE_CRET;
		break;
	case 0xd9:
		gb_anal_mov_ime (op, data[0]);
		op->type2 = R_ANAL_OP_TYPE_MOV;
	case 0xc9:
		op->eob = true;
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
		gb_anal_id (as, op, data[0]);
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
		gb_anal_id (as, op, data[0]);
		break;
	case 0x35:
		op->cycles = 12;
		op->type = R_ANAL_OP_TYPE_SUB;
		gb_anal_id (as, op, data[0]);
		break;
	case 0xc5:
	case 0xd5:
	case 0xe5:
	case 0xf5:
		gb_anal_pp (op, data[0]);
		op->cycles = 16;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		op->type = R_ANAL_OP_TYPE_RPUSH;
		break;
	case 0xc1:
	case 0xd1:
	case 0xe1:
	case 0xf1:
		gb_anal_pp (op, data[0]);
		op->cycles = 12;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case 0xc3:
		if (gb_op_calljump (as, op, data, addr)) {
			op->type = R_ANAL_OP_TYPE_JMP;
			gb_anal_esil_jmp (op);
		} else {
			op->type = R_ANAL_OP_TYPE_UJMP;
		}
		op->eob = true;
		op->cycles = 16;
		op->fail = addr+ilen;
		break;
	case 0x18:					// JR
		op->jump = addr + ilen + (st8)data[1];
		op->fail = addr + ilen;
		gb_anal_esil_jmp (op);
		op->cycles = 12;
		op->eob = true;
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x20:
	case 0x28:
	case 0x30:
	case 0x38:					//JR cond
		gb_anal_cond (op, data[0]);
		op->jump = addr + ilen + (st8)data[1];
		op->fail = addr + ilen;
		gb_anal_esil_cjmp (op, data[0]);
		op->cycles = 12;
		op->failcycles = 8;
		op->eob = true;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0xc2:
	case 0xca:
	case 0xd2:
	case 0xda:
		if (gb_op_calljump (as, op, data, addr)) {
			op->type = R_ANAL_OP_TYPE_CJMP;
		} else {
			op->type = R_ANAL_OP_TYPE_UCJMP;
		}
		op->eob = true;
		gb_anal_cond (op, data[0]);
		gb_anal_esil_cjmp (op, data[0]);
		op->cycles = 16;
		op->failcycles = 12;
		op->fail = addr+ilen;
		break;
	case 0xe9:
		op->cycles = 4;
		op->eob = true;
		op->type = R_ANAL_OP_TYPE_UJMP;
		gb_anal_jmp_hl (op);
		break;
	case 0x76:
#if 0
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->eob = true;			//halt might wait for interrupts
		op->fail = addr + ilen;
		if (len > 1) {
			op->jump = addr + gbOpLength (gb_op[data[1]].type) + ilen;
		}
#else
		//so the above is only semi correct, the exact behaviour of the halt instruction
		//cannot be expressed as op->type or a in a simple esil expression
		//see https://github.com/nitro2k01/little-things-gb/tree/main/double-halt-cancel
		op->type = R_ANAL_OP_TYPE_NULL;
		op->cycles = 4;
		r_strbuf_set (&op->esil, "halt");
#endif
		break;
	case 0xcd:
		if (gb_op_calljump (as, op, data, addr)) {
			op->type = R_ANAL_OP_TYPE_CALL;
		} else {
			op->type = R_ANAL_OP_TYPE_UCALL;
		}
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 24;
		break;
	case 0xc4:
	case 0xcc:
	case 0xd4:
	case 0xdc:
		gb_anal_cond (op, data[0]);
		if (gb_op_calljump (as, op, data, addr)) {
			op->type = R_ANAL_OP_TYPE_CCALL;
		} else {
			op->type = R_ANAL_OP_TYPE_UCCALL;
		}
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_ccall (op, data[0]);
		op->cycles = 24;
		op->failcycles = 12;
		break;
	case 0xc7:				//rst 0
		op->jump = 0x00;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xcf:				//rst 8
		op->jump = 0x08;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xd7:				//rst 16
		op->jump = 0x10;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xdf:				//rst 24
		op->jump = 0x18;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xe7:				//rst 32
		op->jump = 0x20;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xef:				//rst 40
		op->jump = 0x28;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xf7:				//rst 48
		op->jump = 0x30;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xff:				//rst 56
		op->jump = 0x38;
		op->fail = addr + ilen;
		op->eob = true;
		gb_anal_esil_call (op);
		op->cycles = 16;
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0xf3:				//di
	case 0xfb:				//ei
		gb_anal_mov_ime (op, data[0]);
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x37:
		gb_anal_mov_scf (op);
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x27:				//daa
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_XOR;
		r_strbuf_set (&op->esil, "a,daa,a,=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=");
		break;
	case 0x10:				//stop
		op->type = R_ANAL_OP_TYPE_NULL;
		op->cycles = 4;
		r_strbuf_set (&op->esil, "stop");
		break;
	case 0xcb:
		op->nopcode = 2;
		switch (data[1] >> 3) {
		case 0:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_ROL;
			gb_anal_cb_rlc (op, data[1]);
			break;
		case 1:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_ROR;
			gb_anal_cb_rrc (op, data[1]);
			break;
		case 2:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_ROL;
			gb_anal_cb_rl (op, data[1]);
			break;
		case 3:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_ROR;
			gb_anal_cb_rr (op, data[1]);
			break;
		case 4:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_SAL;
			gb_anal_cb_sla (op, data[1]);
			break;
		case 6:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_ROL;
			gb_anal_cb_swap (op, data[1]);
			break;
		case 5:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_SAR;
			gb_anal_cb_sra (op, data[1]);
			break;
		case 7:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_SHR;
			gb_anal_cb_srl (op, data[1]);
			break;
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			op->type = R_ANAL_OP_TYPE_ACMP;
			gb_anal_and_bit (op, data[1]);
			break;			//bit
		case 16:
		case 17:
		case 18:
		case 19:
		case 20:
		case 21:
		case 22:
		case 23:
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			gb_anal_and_res (op, data[1]);
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
			op->cycles = ((data[1] & 7) == 6)? 16: 8;
			gb_anal_or_set (op, data[1]);
			op->type = R_ANAL_OP_TYPE_OR;
			break;			//set
		}
	}
	if (op->type == R_ANAL_OP_TYPE_CALL) {
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
	}
	return op->size > 0;
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	ut8* outbuf = NULL;
	R_FREE (op->bytes);
	int size = gbAsm (op->mnemonic, &outbuf);
	if (size < 1) {
		free (outbuf);
		return false;
	}
	op->bytes = outbuf;
	op->size = size;
	return size > 0;
}

/*
The reg-profile below does not represent the real gameboy registers.
->There is no such thing like m, mpc or mbc. there is only pc.
m and mbc should make it easier to inspect the current mbc-state, because
the mbc can be seen as a register but it isnt. For the Gameboy the mbc is invisble.
*/

static char* regs(RArchSession *as) {
	const char p[] =
		"=PC	mpc\n"
		"=SP	sp\n"
		"=SN	a\n"
		"=A0	af\n"
		"=A1	bc\n"
		"=A2	de\n"
		"=A3	hl\n"

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
	return strdup (p);
}

static int esil_gb_init(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	REsilOp *op = r_esil_get_op (esil, "}{");
	r_esil_set_op (esil, "halt", op->code, 0, 0, R_ESIL_OP_TYPE_CUSTOM, NULL);
	r_esil_set_op (esil, "stop", op->code, 0, 0, R_ESIL_OP_TYPE_CUSTOM, NULL);
	r_esil_set_op (esil, "daa", gb_custom_daa, 1, 1, R_ESIL_OP_TYPE_MATH | R_ESIL_OP_TYPE_CUSTOM, NULL);
	return true;
}

static int esil_gb_fini(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	return true;
}

static int info(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 0;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 3;
	case R_ARCH_INFO_INVOP_SIZE:
		return 1;
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return -1;
}

static bool esil_cb(RArchSession *as, RArchEsilAction action) {
	REsil *esil = as->arch->esil;
	if (!esil) {
		return false;
	}
	switch (action) {
	case R_ARCH_ESIL_ACTION_INIT:
		esil_gb_init (esil);
		break;
	case R_ARCH_ESIL_ACTION_FINI:
		esil_gb_fini (esil);
		break;
	default:
		return false;
	}
	return true;
}

const RArchPlugin r_arch_plugin_gb = {
	.meta = {
		.name = "gb",
		.author = "condret",
		.desc = "Gameboy CPU (modified Z80)",
		.license = "LGPL-3.0-only",
	},
	.arch = "z80",
	.info = info,
	.regs = regs,
	.bits = R_SYS_BITS_PACK1 (16),
	.decode = decode,
	.encode = encode,
	.esilcb = esil_cb,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_gb,
	.version = R2_VERSION
};
#endif
