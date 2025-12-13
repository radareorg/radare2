/* radare - LGPL - Copyright 2024 - pancake, condret */

#include <r_esil.h>
#include <r_anal.h>

#if __wasi__ || EMSCRIPTEN
#define FE_OVERFLOW 0
#define feclearexcept(x)
#endif
#include <math.h>
#include <float.h>
#include <fenv.h>

#define IFDBG if (esil->verbose > 1)
#define OP(v, w, x, y, z) r_esil_set_op (esil, v, w, x, y, z, NULL)
#define OP2(v, w, x, y, z, i) r_esil_set_op (esil, v, w, x, y, z, i)
#define	OT_UNK	R_ESIL_OP_TYPE_UNKNOWN
#define	OT_CTR	R_ESIL_OP_TYPE_CONTROL_FLOW
#define	OT_MATH	R_ESIL_OP_TYPE_MATH
#define	OT_REGW	R_ESIL_OP_TYPE_REG_WRITE
#define	OT_MEMW	R_ESIL_OP_TYPE_MEM_WRITE
#define	OT_MEMR	R_ESIL_OP_TYPE_MEM_READ
#define	OT_FLAG R_ESIL_OP_TYPE_FLAG
#define	OT_TRAP R_ESIL_OP_TYPE_TRAP

R_IPI bool alignCheck(REsil *esil, ut64 addr);

/// XXX R2_600 - must be internal imho
R_API bool r_esil_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
#if USE_NEW_ESIL
	R_RETURN_VAL_IF_FAIL (buf && esil && esil->mem_if.mem_read, false);
	addr &= esil->addrmask;
#else
	R_RETURN_VAL_IF_FAIL (buf && esil, false);
	addr &= esil->addrmask;
	bool ret = false;
	if (esil->cb.hook_mem_read) {
		ret = esil->cb.hook_mem_read (esil, addr, buf, len);
	}
#endif
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
#if USE_NEW_ESIL
	if (R_UNLIKELY (!r_esil_mem_read_silent (esil, addr, buf, len))) {
		return false;
	}
	ut32 i;
	if (!r_id_storage_get_lowest (&esil->voyeur[R_ESIL_VOYEUR_MEM_READ], &i)) {
		return true;
	}
	do {
		REsilVoyeur *voy = r_id_storage_get (&esil->voyeur[R_ESIL_VOYEUR_MEM_READ], i);
		voy->mem_read (voy->user, addr, buf, len);
	} while (r_id_storage_get_next (&esil->voyeur[R_ESIL_VOYEUR_MEM_READ], &i));
	return true;
#else
	if (!ret && esil->cb.mem_read) {
		if (ret = esil->cb.mem_read (esil, addr, buf, len), (!ret && esil->iotrap)) {
			esil->trap = R_ANAL_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
	}
	IFDBG {
		size_t i;
		eprintf ("0x%08" PFMT64x " R> ", addr);
		for (i = 0; i < len; i++) {
			eprintf ("%02x", buf[i]);
		}
		eprintf ("\n");
	}
	return ret;
#endif
}

static bool r_esil_fire_trap(REsil *esil, int trap_type, int trap_code) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	if (esil->cmd && R_STR_ISNOTEMPTY (esil->cmd_trap)) {
		if (esil->cmd (esil, esil->cmd_trap, trap_type, trap_code)) {
			return true;
		}
	}
#if 0
	REsilTrapCB icb;
	icb = (REsilTrapCB)sdb_ptr_get (esil->traps, i, 0);
	return icb (esil, trap_type, trap_code);
#endif
	return false;
}

static bool isnum(REsil *esil, const char *str, ut64 *num) {
	R_RETURN_VAL_IF_FAIL (esil && str, false);
	if (isdigit (*str)) {
		if (num) {
			*num = r_num_get (NULL, str);
		}
		return true;
	}
	if (num) {
		*num = 0;
	}
	return false;
}

R_IPI bool isregornum(REsil *esil, const char *str, ut64 *num) {
	if (!r_esil_reg_read (esil, str, num, NULL)) {
		if (!isnum (esil, str, num)) {
			return false;
		}
	}
	return true;
}

/* pop Register or Number */
static bool popRN(REsil *esil, ut64 *n) {
	char *str = r_esil_pop (esil);
	if (str) {
		bool ret = isregornum (esil, str, n);
		free (str);
		return ret;
	}
	return false;
}

static ut8 esil_internal_sizeof_reg(REsil *esil, const char *r) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal && esil->anal->reg && r, 0);
	RRegItem *ri = r_reg_get (esil->anal->reg, r, -1);
	if (ri) {
		ut8 reg_size = ri->size; // why a reg size cant be > 256 bits?
		r_unref (ri);
		return reg_size;
	}
	return 0;
}

static bool r_esil_signext(REsil *esil, bool assign) {
	bool ret = false;
	ut64 src, dst;

	char *p_src = r_esil_pop (esil);
	if (!p_src) {
		return false;
	}

	if (!r_esil_get_parm (esil, p_src, &src)) {
		R_LOG_DEBUG ("esil_of: empty stack");
		free (p_src);
		return false;
	}

	char *p_dst = r_esil_pop (esil);
	if (!p_dst) {
		free (p_src);
		return false;
	}

	if (!r_esil_get_parm (esil, p_dst, &dst)) {
		R_LOG_DEBUG ("esil_of: empty stack");
		free (p_src);
		free (p_dst);
		return false;
	}
	free (p_dst);

	// Make sure the other bits are 0
	ut64 m = 0;
	if (dst > 0 && dst < 64) {
		src &= UT64_MAX >> (64 - dst);
		m = 1ULL << (dst - 1);
	} else if (dst == 0) {
		src = 0;
	}

	// dst = (dst & ((1U << src_bit) - 1)); // clear upper bits
	if (assign) {
		ret = r_esil_reg_write (esil, p_src, ((src ^ m) - m));
	} else {
		ret = r_esil_pushnum (esil, ((src ^ m) - m));
	}

	free (p_src);
	return ret;
}

// sign extension operator for use in idiv, imul, movsx*
// and other instructions involving signed values, extends n bit value to 64 bit value
// example : >"ae 8,0x81,~" ( <src bit width>,<value>,~ )
// output  : 0xffffffffffffff81
static bool esil_signext(REsil *esil) {
	return r_esil_signext (esil, false);
}

// sign extension assignement
// example : > "ae 0x81,a0,="
//           > "ae 8,a0,~="   ( <src bit width>,register,~= )
// output  : > ar a0
//           0xffffff81
static bool esil_signexteq(REsil *esil) {
	return r_esil_signext (esil, true);
}

static bool esil_zf(REsil *esil) {
	return r_esil_pushnum (esil, !(esil->cur & r_num_genmask (esil->lastsz - 1)));
}

// checks if there was a carry from bit x (x,$c)
static bool esil_cf(REsil *esil) {
	char *src = r_esil_pop (esil);
	if (!src) {
		return false;
	}
	if (r_esil_get_parm_type (esil, src) != R_ESIL_PARM_NUM) {
		//I'd wish we could enforce consts here
		//I can't say why, but I feel like "al,$c" would be cancer af
		//	- condret
		free (src);
		return false;
	}
	ut64 bit;
	r_esil_get_parm (esil, src, &bit);
	free (src);
	//carry from bit <src>
	//range of src goes from 0 to 63
	//
	//implements bit mod 64
	const ut64 mask = r_num_genmask (bit & 0x3f);
	return r_esil_pushnum (esil, (esil->cur & mask) < (esil->old & mask));
}

// checks if there was a borrow from bit x (x,$b)
static bool esil_bf(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	char *src = r_esil_pop (esil);
	if (!src) {
		return false;
	}
	if (r_esil_get_parm_type (esil, src) != R_ESIL_PARM_NUM) {
		free (src);
		return false;
	}
	ut64 bit;
	r_esil_get_parm (esil, src, &bit);
	free (src);
	//borrow from bit <src>
	//range of src goes from 1 to 64
	//	you cannot borrow from bit 0, bc bit -1 cannot not exist
	//
	//implements (bit - 1) mod 64
	const ut64 mask = r_num_genmask ((bit + 0x3f) & 0x3f);
	return r_esil_pushnum (esil, (esil->old & mask) < (esil->cur & mask));
}

static bool esil_pf(REsil *esil) {
	// Set if the number of set bits in the least significant _byte_ is a multiple of 2.
	//   - Taken from: https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits
	const ut64 c1 = 0x0101010101010101ULL;
	const ut64 c2 = 0x8040201008040201ULL;
	const ut64 c3 = 0x1FF;
	// Take only the least significant byte.
	ut64 lsb = esil->cur & 0xff;
	return r_esil_pushnum (esil, !((((lsb * c1) & c2) % c3) & 1));
}

// like carry
// checks overflow from bit x (x,$o)
//	x,$o ===> x,$c,x-1,$c,^
static bool esil_of(REsil *esil) {
	char *p_bit = r_esil_pop (esil);

	if (!p_bit) {
		return false;
	}

	if (r_esil_get_parm_type (esil, p_bit) != R_ESIL_PARM_NUM) {
		free (p_bit);
		return false;
	}
	ut64 bit;

	if (!r_esil_get_parm (esil, p_bit, &bit)) {
		R_LOG_DEBUG ("esil_of: empty stack");
		free (p_bit);
		return false;
	}
	free (p_bit);

	const ut64 m[2] = {r_num_genmask (bit & 0x3f), r_num_genmask ((bit + 0x3f) & 0x3f)};
	const ut64 result = ((esil->cur & m[0]) < (esil->old & m[0])) ^ ((esil->cur & m[1]) < (esil->old & m[1]));
	ut64 res = r_esil_pushnum (esil, result);
	return res;
}

//checks sign bit at x (x,$s)
static bool esil_sf(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);

	char *p_size = r_esil_pop (esil);
	if (!p_size) {
		R_LOG_WARN ("$sf cannot pop sign bit value (for example: 31,$s,s,:=)");
		return false;
	}

	if (r_esil_get_parm_type (esil, p_size) != R_ESIL_PARM_NUM) {
		free (p_size);
		return false;
	}
	ut64 size, num;
	r_esil_get_parm (esil, p_size, &size);
	free (p_size);

	if (size > 63) {
		num = 0;
	} else {
		num = (esil->cur >> size) & 1;
	}
	return r_esil_pushnum (esil, num);
}

static bool esil_ds(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	return r_esil_pushnum (esil, esil->delay);
}

static bool esil_jt(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	return r_esil_pushnum (esil, esil->jump_target);
}

static bool esil_js(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	return r_esil_pushnum (esil, esil->jump_target_set);
}

static bool esil_weak_eq(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal, false);
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (!(dst && src && (r_esil_get_parm_type (esil, dst) == R_ESIL_PARM_REG))) {
		free (dst);
		free (src);
		return false;
	}

	ut64 src_num;
	if (r_esil_get_parm (esil, src, &src_num)) {
		(void)r_esil_reg_write (esil, dst, src_num);
		free (src);
		free (dst);
		return true;
	}

	free (src);
	free (dst);
	return false;
}

static bool esil_eq(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (!src || !dst) {
		R_LOG_DEBUG ("esil_eq cant pop two values from stack at 0x%08"PFMT64x, esil->addr);
		free (src);
		free (dst);
		return false;
	}
	bool is128reg = false;
	bool ispacked = false;
	RRegItem *ri = r_reg_get (esil->anal->reg, dst, -1);
	if (ri) {
		is128reg = ri->size == 128;
		ispacked = ri->packed_size > 0;
		r_unref (ri);
	} else {
		R_LOG_DEBUG ("esil_eq: %s is not a register", dst);
	}
	if (is128reg && esil->stackptr > 0) {
		char *src2 = r_esil_pop (esil); // pop the higher 64bit value
		ut64 n0 = r_num_get (NULL, src);
		ut64 n1 = r_num_get (NULL, src2);
		ret = r_esil_reg_write (esil, dst, n1);
		char *dst2 = r_str_newf ("%sh", dst); // q0 -> q0h
		ret = r_esil_reg_write (esil, dst2, n0);
		free (dst2);
	} else if (ispacked) {
		char *src2 = r_esil_pop (esil);
		char *newreg = r_str_newf ("%sl", dst);
		if (r_esil_get_parm (esil, src2, &num2)) {
			ret = r_esil_reg_write (esil, newreg, num2);
		} else {
			ut64 n0 = r_num_get (NULL, src);
			ret = r_esil_reg_write (esil, dst, n0);
		}
		free (newreg);
		free (src2);
#if USE_NEW_ESIL
	} else if (src && dst && r_esil_reg_read_silent (esil, dst, &num, NULL)) {
#else
	} else if (src && dst && r_esil_reg_read_nocallback (esil, dst, &num, NULL)) {
#endif
		if (r_esil_get_parm (esil, src, &num2)) {
			ret = r_esil_reg_write (esil, dst, num2);
			esil->cur = num2;
			esil->old = num;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
		} else {
			R_LOG_DEBUG ("esil_eq: invalid src");
		}
	} else {
		R_LOG_DEBUG ("esil_eq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_neg(REsil *esil) {
	bool ret = false;
	char *src = r_esil_pop (esil);
	if (src) {
		ut64 num;
		if (r_esil_get_parm (esil, src, &num)) {
			r_esil_pushnum (esil, !num);
			ret = true;
		} else {
			if (isregornum (esil, src, &num)) {
				ret = true;
				r_esil_pushnum (esil, !num);
			} else {
				R_LOG_WARN ("0x%08"PFMT64x" esil_neg: unknown reg %s", esil->addr, src);
			}
		}
	} else {
		R_LOG_DEBUG ("esil_neg: empty stack");
	}
	free (src);
	return ret;
}

static bool esil_negeq(REsil *esil) {
	bool ret = false;
	ut64 num;
	char *src = r_esil_pop (esil);
	if (src && r_esil_reg_read (esil, src, &num, NULL)) {
		num = !num;
		r_esil_reg_write (esil, src, num);
		ret = true;
	} else {
		R_LOG_DEBUG ("esil_negeq: empty stack");
	}
	free (src);
	//r_esil_pushnum (esil, ret);
	return ret;
}

static bool esil_nop(REsil *esil) {
	return true;
}

static bool esil_andeq(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num & num2;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			r_esil_reg_write (esil, dst, num & num2);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_andeq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_oreq(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num | num2;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_esil_reg_write (esil, dst, num | num2);
		} else {
			R_LOG_DEBUG ("esil_ordeq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_xoreq(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
				esil->old = num;
				esil->cur = num ^ num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_esil_reg_write (esil, dst, num ^ num2);
		} else {
			R_LOG_DEBUG ("esil_xoreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

#if 0
static int esil_interrupt_linux_i386(REsil *esil) { 		//move this into a plugin
	ut32 sn, ret = false;
	char *usn = r_esil_pop (esil);
	if (usn) {
		sn = (ut32) r_num_get (NULL, usn);
	} else sn = 0x80;

	if (sn == 3) {
		// trap
		esil->trap = R_ANAL_TRAP_BREAKPOINT;
		esil->trap_code = 3;
		return -1;
	}

	if (sn != 0x80) {
		R_LOG_WARN ("Unhandled interrupt 0x%x at 0x%08"PFMT64x, sn, esil->pc);
		esil->trap = R_ANAL_TRAP_UNHANDLED;
		esil->trap_code = sn;
		return -1;
	}
#undef r
#define r(x) r_reg_getv (esil->anal->reg, "##x##")
#undef rs
#define rs(x, y) r_reg_setv (esil->anal->reg, "##x##", y)
	switch (r(eax)) {
	case 1:
		printf ("exit(%d)\n", (int)r(ebx));
		rs(eax, -1);
		// never return. stop execution somehow, throw an exception
		break;
	case 3:
		ret = r(edx);
		printf ("ret:%d = read(fd:%"PFMT64d", ptr:0x%08"PFMT64x", len:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	case 4:
		ret = r(edx);
		printf ("ret:%d = write(fd:%"PFMT64d", ptr:0x%08"PFMT64x", len:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	case 5:
		ret = -1;
		printf ("fd:%d = open(file:0x%08"PFMT64x", mode:%"PFMT64d", perm:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	}
#undef r
#undef rs
	return 0;
}
#endif

static bool esil_trap(REsil *esil) {
	ut64 s, d;
	if (popRN (esil, &s) && popRN (esil, &d)) {
		esil->trap = s;
		esil->trap_code = d;
		return r_esil_fire_trap (esil, (int)s, (int)d);
	}
	R_LOG_DEBUG ("esil_trap: missing parameters in stack");
	if (esil->cmd_trap) {
		esil->cmd (esil, esil->cmd_trap, esil->addr, R_ANAL_TRAP_INVALID);
	}
	return false;
}

static bool esil_bits(REsil *esil) {
	ut64 s;
	if (popRN (esil, &s)) {
		if (esil->anal && esil->anal->coreb.setArchBits) {
			esil->anal->coreb.setArchBits (esil->anal->coreb.core, NULL, s);
		}
		return true;
	}
	R_LOG_DEBUG ("esil_bits: missing parameters in stack");
	return false;
}

static bool esil_interrupt(REsil *esil) {
	ut64 interrupt;
	if (popRN (esil, &interrupt)) {
		return r_esil_fire_interrupt (esil, (ut32)interrupt);
	}
	return false;
}

static bool esil_syscall(REsil *esil) {
	ut64 sc;
	if (popRN (esil, &sc)) {
		return r_esil_do_syscall (esil, (ut32)sc);
	}
	return false;
}

static bool esil_cmd(REsil *esil) {
	char *str = r_esil_pop (esil);
	if (str) {
		if (esil->anal && esil->anal->coreb.setArchBits) {
			esil->anal->coreb.cmd (esil->anal->coreb.core, str);
		}
	}
	return false;
}

// NOTE on following comparison functions:
// The push to top of the stack is based on a
// signed compare (as this causes least surprise to the users).
// If an unsigned comparison is necessary, one must not use the
// result pushed onto the top of the stack, but rather test the flags which
// are set as a result of the compare.

static int signed_compare_gt(ut64 a, ut64 b, ut64 size) {
	int result;
	switch (size) {
	case 1:  result = (a & 1) > (b & 1);
		break;
	case 8:  result = (st8) a > (st8) b;
		break;
	case 16: result = (st16) a > (st16) b;
		break;
	case 32: result = (st32) a > (st32) b;
		break;
	case 64:
	default: result = (st64) a > (st64) b;
		break;
	}
	return result;
}

static void pushnums(REsil *esil, const char *src, ut64 num2, const char *dst, ut64 num) {
	R_RETURN_IF_FAIL (esil);
	esil->old = num;
	esil->cur = num - num2;
	RReg *reg = esil->anal->reg;
	RRegItem *ri = r_reg_get (reg, dst, -1);
	if (ri) {
		esil->lastsz = esil_internal_sizeof_reg (esil, dst);
		r_unref (ri);
		return;
	}
	if (ri = r_reg_get (reg, src, -1), ri) {
		esil->lastsz = esil_internal_sizeof_reg (esil, src);
		r_unref (ri);
		return;
	}
	// default size is set to 64 as internally operands are ut64
	esil->lastsz = 64;
}

// This function also sets internal vars which is used in flag calculations.
static bool esil_cmp(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	ut64 num, num2;
	bool ret = false;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			ret = true;
			pushnums (esil, src, num2, dst, num);
		}
	}
	free (dst);
	free (src);
	return ret;
}

#if 1
// needed for COSMAC
static bool esil_regalias(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	ut64 num;
	bool ret = false;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &num)) {
		ret = true;
		int kind = r_reg_alias_fromstring (dst);
		if (kind != -1) {
			r_reg_alias_setname (esil->anal->reg, kind, src);
		}
	}
	free (dst);
	free (src);
	return ret;
}
#endif

#if 0
x86 documentation:
CF - carry flag -- Set on high-order bit carry or borrow; cleared otherwise
	num>>63
PF - parity flag
	(num&0xff)
	Set if low-order eight bits of result contain an even number of "1" bits; cleared otherwise
ZF - zero flags
	Set if result is zero; cleared otherwise
	zf = num?0:1;
SF - sign flag
	Set equal to high-order bit of result (0 if positive 1 if negative)
	sf = ((st64)num)<0)?1:0;
OF - overflow flag
	if (a>0&&b>0 && (a+b)<0)
	Set if result is too large a positive number or too small a negative number (excluding sign bit) to fit in destination operand; cleared otherwise

JBE: CF = 1 || ZF = 1

#endif

/*
 * Expects a string in the stack. Each char of the string represents a CPU flag.
 * Those relations are associated by the CPU itself and are used to move values
 * from the internal ESIL into the RReg instance.
 *
 * For example:
 *   zco,?=     # update zf, cf and of
 *
 * If we want to update the esil value of a specific flag we use the =? command
 *
 *    zf,z,=?    # esil[zf] = r_reg[zf]
 *
 * Defining new cpu flags
 */
#if 0
#define FLG(x) R_ESIL_FLAG_##x
#define cpuflag(x, y)\
if (esil) {\
	if (y) { \
		R_BIT_SET (&esil->flags, FLG (x));\
	} else { \
		R_BIT_UNSET (&esil->flags, FLG (x));\
	} \
}
static int esil_ifset(REsil *esil) {
	char *s, *src = r_esil_pop (esil);
	for (s=src; *s; s++) {
		switch (*s) {
		case 'z':
			r_esil_reg_write (esil, "zf", R_BIT_CHK(&esil->flags, FLG(ZERO)));
			break;
		case 'c':
			r_esil_reg_write (esil, "cf", R_BIT_CHK(&esil->flags, FLG(CARRY)));
			break;
		case 'o':
			r_esil_reg_write (esil, "of", R_BIT_CHK(&esil->flags, FLG(OVERFLOW)));
			break;
		case 'p':
			r_esil_reg_write (esil, "pf", R_BIT_CHK(&esil->flags, FLG(PARITY)));
			break;
		}
	}
	free (src);
	return 0;
}
#endif

static bool esil_if (REsil *esil) {
	ut64 num = 0LL;
	if (esil->skip) {
		esil->skip++;
		return true;
	}
	bool ret = false;
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &num)) {
		// condition not matching, skipping until
		if (!num) {
			esil->skip++;
		}
		ret = true;
	}
	free (src);
	return ret;
}

static bool esil_lsl(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			if (num2 > sizeof (ut64) * 8) {
				R_LOG_DEBUG ("esil_lsl: shift is too big");
			} else {
				const ut64 shift = (num2 > 63)? 0: num << num2;
				r_esil_pushnum (esil, shift);
				ret = true;
			}
		} else {
			R_LOG_DEBUG ("esil_lsl: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_lsleq(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			if (num2 > sizeof (ut64) * 8) {
				R_LOG_DEBUG ("esil_lsleq: shift is too big");
			} else {
				esil->old = num;
				if (num2 > 63) {
					num = 0;
				} else {
					num <<= num2;
				}
				esil->cur = num;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				r_esil_reg_write (esil, dst, num);
				ret = true;
			}
		} else {
			R_LOG_DEBUG ("esil_lsleq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_lsr(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			ut64 res = num >> R_MIN (num2, 63);
			r_esil_pushnum (esil, res);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_lsr: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_lsreq(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			if (num2 > 63) {
				if (esil->verbose) {
					R_LOG_WARN ("Invalid shift at 0x%08"PFMT64x, esil->addr);
				}
				num2 = 63;
			}
			esil->old = num;
			num >>= num2;
			esil->cur = num;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			r_esil_reg_write (esil, dst, num);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_lsreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_asreq(REsil *esil) {
	bool ret = false;
	int regsize = 0;
	ut64 op_num, param_num;
	char *op = r_esil_pop (esil);
	char *param = r_esil_pop (esil);
	if (op && r_esil_get_parm_size (esil, op, &op_num, &regsize)) {
		if (param && r_esil_get_parm (esil, param, &param_num)) {
			ut64 mask = (regsize - 1);
			param_num &= mask;
			bool isNegative;
			if (regsize == 32) {
				isNegative = ((st32)op_num)<0;
				st32 snum = op_num;
				op_num = snum;
			} else {
				isNegative = ((st64)op_num)<0;
			}
			if (isNegative) {
				if (regsize == 32) {
					op_num = -(st64)op_num;
					if (op_num >> param_num) {
						op_num >>= param_num;
						op_num = -(st64)op_num;
					} else {
						op_num = -1;
					}
				} else {
					ut64 mask = (regsize - 1);
					param_num &= mask;
					ut64 left_bits = 0;
					int shift = regsize - 1;
					if (shift < 0 || shift > regsize - 1) {
						if (esil->verbose) {
							R_LOG_WARN ("Invalid asreq shift of %d at 0x%"PFMT64x, shift, esil->addr);
						}
						shift = 0;
					}
					if (param_num > regsize - 1) {
						// capstone bug?
						if (esil->verbose) {
							R_LOG_WARN ("Invalid asreq shift of %"PFMT64d" at 0x%"PFMT64x, param_num, esil->addr);
						}
						param_num = 30;
					}
					if (shift >= 63) {
						// LL can't handle LShift of 63 or more
						if (esil->verbose) {
							R_LOG_WARN ("Invalid asreq shift of %d at 0x%08"PFMT64x, shift, esil->addr);
						}
					} else if (op_num & (1LL << shift)) {
						left_bits = (1 << param_num) - 1;
						left_bits <<= regsize - param_num;
					}
					op_num = left_bits | (op_num >> param_num);
				}
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			esil->cur = res;
			esil->lastsz = esil_internal_sizeof_reg (esil, op);
			r_esil_reg_write (esil, op, res);
			// r_esil_pushnum (esil, res);
			ret = true;
		} else {
			if (esil->verbose) {
				R_LOG_WARN ("esil_asr: empty stack");
			}
		}
	}
	free (param);
	free (op);
	return ret;
}

static bool esil_asr(REsil *esil) {
	bool ret = false;
	int regsize = 0;
	ut64 op_num = 0, param_num = 0;
	char *op = r_esil_pop (esil);
	char *param = r_esil_pop (esil);
	if (op && r_esil_get_parm_size (esil, op, &op_num, &regsize)) {
		if (param && r_esil_get_parm (esil, param, &param_num)) {
			if (param_num > regsize - 1) {
				// capstone bug?
				if (esil->verbose) {
					R_LOG_WARN ("Invalid asr shift of %"PFMT64d" at 0x%"PFMT64x, param_num, esil->addr);
				}
				param_num = 30;
			}
			bool isNegative;
			if (regsize == 32) {
				isNegative = ((st32)op_num) < 0;
				st32 snum = op_num;
				op_num = snum;
			} else {
				isNegative = ((st64)op_num) < 0;
			}
			if (isNegative) {
				ut64 mask = (regsize - 1);
				param_num &= mask;
				ut64 left_bits = 0;
				if (regsize <= 64) {
					if (op_num & (1ULL << (regsize - 1))) {
						if (regsize - param_num >= 64) {
							left_bits = 0;
						} else {
							left_bits = (1ULL << param_num) - 1;
							left_bits <<= regsize - param_num;
						}
					}
				}
				op_num = left_bits | (op_num >> param_num);
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			r_esil_pushnum (esil, res);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_asr: empty stack");
		}
	}
	free (param);
	free (op);
	return ret;
}

static bool esil_ror(REsil *esil) {
	bool ret = false;
	int regsize;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num >> num2) | (num << ((-(st64)num2) & mask));
			r_esil_pushnum (esil, res);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_ror: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_roreq(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			int regsize = esil_internal_sizeof_reg (esil, dst);
			if (regsize < 1) {
				regsize = 64;
			}
			ut64 mask = (regsize - 1);
			num2 &= mask;
			esil->old = num;
			num = (num >> num2) | (num << ((-(st64)num2) & mask));
			num &= r_num_genmask (regsize - 1);
			esil->cur = num;
			esil->lastsz = regsize;
			r_esil_reg_write (esil, dst, num);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_roreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_rol(REsil *esil) {
	bool ret = false;
	int regsize;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num << num2) | (num >> ((-(st64)num2) & mask));
			r_esil_pushnum (esil, res);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_rol: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_roleq(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			int regsize = esil_internal_sizeof_reg (esil, dst);
			if (regsize < 1) {
				regsize = 64;
			}
			ut64 mask = (regsize - 1);
			num2 &= mask;
			esil->old = num;
			num = (num << num2) | (num >> ((-(st64)num2) & mask));
			num &= r_num_genmask (regsize - 1);
			esil->cur = num;
			esil->lastsz = regsize;
			r_esil_reg_write (esil, dst, num);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_roleq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_and(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			num &= num2;
			r_esil_pushnum (esil, num);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_and: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_xor(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			num ^= num2;
			r_esil_pushnum (esil, num);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_xor: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_or(REsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			num |= num2;
			r_esil_pushnum (esil, num);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_xor: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_break(REsil *esil) {
	esil->parse_stop = 1;
	return 1;
}

static bool esil_clear(REsil *esil) {
	char *r;
	while ((r = r_esil_pop (esil))) {
		free (r);
	}
	return 1;
}

static bool esil_todo(REsil *esil) {
	esil->parse_stop = 2;
	return 1;
}

static bool esil_goto(REsil *esil) {
	ut64 num = 0;
	char *src = r_esil_pop (esil);
	if (src && *src && r_esil_get_parm (esil, src, &num)) {
		esil->parse_goto = num;
	}
	free (src);
	return 1;
}

static bool esil_pop(REsil *esil) {
	char *dst = r_esil_pop (esil);
	free (dst);
	return 1;
}

static bool esil_mod(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_get_parm (esil, dst, &d)) {
			if (s == 0) {
				R_LOG_DEBUG ("0x%08"PFMT64x" esil_mod: Division by zero!", esil->addr);
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_esil_pushnum (esil, d % s);
			}
			ret = true;
		}
	} else {
		R_LOG_DEBUG ("esil_mod: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_signed_mod(REsil *esil) {
	bool ret = false;
	st64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, (ut64 *)&s)) {
		if (dst && r_esil_get_parm (esil, dst, (ut64 *)&d)) {
			if (ST64_DIV_OVFCHK (d, s)) {
				R_LOG_DEBUG ("0x%08"PFMT64x" esil_mod: Division by zero!", esil->addr);
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_esil_pushnum (esil, d % s);
			}
			ret = true;
		}
	} else {
		R_LOG_DEBUG ("esil_smod: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_modeq(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				esil->old = d;
				esil->cur = d % s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				r_esil_reg_write (esil, dst, d % s);
			} else {
				R_LOG_DEBUG ("esil_modeq: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_modeq: empty stack");
		}
	} else {
		R_LOG_DEBUG ("esil_modeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_div(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_get_parm (esil, dst, &d)) {
			if (s == 0) {
				R_LOG_DEBUG ("esil_div: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_esil_pushnum (esil, d / s);
			}
			ret = true;
		}
	} else {
		R_LOG_DEBUG ("esil_div: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_signed_div(REsil *esil) {
	bool ret = false;
	st64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, (ut64 *)&s)) {
		if (dst && r_esil_get_parm (esil, dst, (ut64 *)&d)) {
			if (ST64_DIV_OVFCHK (d, s)) {
				R_LOG_DEBUG ("esil_div: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_esil_pushnum (esil, d / s);
			}
			ret = true;
		}
	} else {
		R_LOG_DEBUG ("esil_div: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_diveq(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				esil->old = d;
				esil->cur = d / s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				r_esil_reg_write (esil, dst, d / s);
			} else {
				// eprintf ("0x%08"PFMT64x" esil_diveq: Division by zero!\n", esil->addr);
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_diveq: empty stack");
		}
	} else {
		R_LOG_DEBUG ("esil_diveq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

// 128 bit multiplication result
static void mult64to128(ut64 op1, ut64 op2, ut64 *hi, ut64 *lo) {
	ut64 u1 = (op1 & 0xffffffff);
	ut64 v1 = (op2 & 0xffffffff);
	ut64 t = (u1 * v1);
	ut64 w3 = (t & 0xffffffff);
	ut64 k = (t >> 32);

	op1 >>= 32;
	t = (op1 * v1) + k;
	k = (t & 0xffffffff);
	ut64 w1 = (t >> 32);

	op2 >>= 32;
	t = (u1 * op2) + k;
	k = (t >> 32);

	*hi = (op1 * op2) + w1 + k;
	*lo = (t << 32) + w3;
}

static bool esil_long_mul(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	ut64 hi, lo;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_get_parm (esil, dst, &d)) {
			mult64to128(s, d, &hi, &lo);
			r_esil_pushnum (esil, hi);
			r_esil_pushnum (esil, lo);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_long_mul: empty stack");
		}
	} else {
		R_LOG_DEBUG ("esil_long_mul: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_mul(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_get_parm (esil, dst, &d)) {
			r_esil_pushnum (esil, d * s);
			ret = true;
		} else {
			R_LOG_DEBUG ("esil_mul: empty stack");
		}
	} else {
		R_LOG_DEBUG ("esil_mul: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_muleq(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_reg_read (esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d * s;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_esil_reg_write (esil, dst, s * d);
		} else {
			R_LOG_DEBUG ("esil_muleq: empty stack");
		}
	} else {
		R_LOG_DEBUG ("esil_muleq: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_add(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (R_LIKELY (src && dst)) {
		if (r_esil_get_parm (esil, src, &s) && r_esil_get_parm (esil, dst, &d)) {
			r_esil_pushnum (esil, s + d);
			ret = true;
		}
	} else {
		R_LOG_DEBUG ("esil_add: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_inc(REsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		s++;
		ret = r_esil_pushnum (esil, s);
	} else {
		R_LOG_DEBUG ("esil_inc: invalid parameters");
	}
	free (src);
	return ret;
}

static bool esil_inceq(REsil *esil) {
	bool ret = false;
	ut64 sd;
	char *src_dst = r_esil_pop (esil);
	if (src_dst && (r_esil_get_parm_type (esil, src_dst) == R_ESIL_PARM_REG) && r_esil_get_parm (esil, src_dst, &sd)) {
		// inc rax
		esil->old = sd++;
		esil->cur = sd;
		r_esil_reg_write (esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg (esil, src_dst);
		ret = true;
	} else {
		R_LOG_DEBUG ("esil_inceq: invalid parameters");
	}
	free (src_dst);
	return ret;
}

static bool esil_addeq(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_reg_read (esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d + s;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_esil_reg_write (esil, dst, s + d);
		}
	} else {
		R_LOG_DEBUG ("esil_addeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_subeq(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		if (dst && r_esil_reg_read (esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d - s;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_esil_reg_write (esil, dst, d - s);
		}
	} else {
		R_LOG_DEBUG ("esil_subeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}


static bool esil_sub(REsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if ((src && r_esil_get_parm (esil, src, &s)) && (dst && r_esil_get_parm (esil, dst, &d))) {
		ret = r_esil_pushnum (esil, d - s);
	} else {
		R_LOG_DEBUG ("esil_sub: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_dec(REsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		s--;
		ret = r_esil_pushnum (esil, s);
	} else {
		R_LOG_DEBUG ("esil_dec: invalid parameters");
	}
	free (src);
	return ret;
}

static bool esil_deceq(REsil *esil) {
	bool ret = false;
	ut64 sd;
	char *src_dst = r_esil_pop (esil);
	if (src_dst && (r_esil_get_parm_type (esil, src_dst) == R_ESIL_PARM_REG) && r_esil_get_parm (esil, src_dst, &sd)) {
		esil->old = sd;
		sd--;
		esil->cur = sd;
		r_esil_reg_write (esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg (esil, src_dst);
		ret = true;
	} else {
		R_LOG_DEBUG ("esil_deceq: invalid parameters");
	}
	free (src_dst);
	return ret;
}

/* POKE */
static bool esil_poke_n(REsil *esil, int bits) {
	ut64 bitmask = r_num_genmask (bits - 1);
	ut64 num, addr;
	ut8 b[8] = {0};
	ut64 n;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	int bytes = R_MIN (sizeof (b), bits / 8);
	if (bits % 8) {
		free (src);
		free (dst);
		return false;
	}
	bool ret = false;
	//eprintf ("GONA POKE %d src:%s dst:%s\n", bits, src, dst);
	char *src2 = NULL;
	if (src && r_esil_get_parm (esil, src, &num)) {
		if (dst && r_esil_get_parm (esil, dst, &addr)) {
			if (bits == 128) {
				char reg[32];
				r_str_ncpy (reg, src, sizeof (reg) - 2);
				size_t last = strlen (reg);
				reg[last + 1] = 0;
				reg[last] = 'l';
				ut64 loow = r_reg_getv (esil->anal->reg, reg);
				reg[last] = 'h';
				ut64 high = r_reg_getv (esil->anal->reg, reg);
				ret = r_esil_mem_write (esil, addr, (const ut8*)&loow, 8);
				ret = r_esil_mem_write (esil, addr + 8, (const ut8*)&high, 8);
#if 0
				src2 = r_esil_pop (esil);
				if (src2 && r_esil_get_parm (esil, src2, &num2)) {
					r_write_ble (b, num, R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config), 64);
					ret = r_esil_mem_write (esil, addr, b, bytes);
					if (ret == 0) {
						r_write_ble (b, num2, R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config), 64);
						ret = r_esil_mem_write (esil, addr + 8, b, bytes);
					}
					goto out;
				}
				ret = false;
#endif
				goto out;
			}
			// this is a internal peek performed before a poke
			// we disable hooks to avoid run hooks on internal peeks
			void * oldhook = (void*)esil->cb.hook_mem_read;
			esil->cb.hook_mem_read = NULL;
			r_esil_mem_read (esil, addr, b, bytes);
			esil->cb.hook_mem_read = oldhook;
			n = r_read_ble64 (b, R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config));
			esil->old = n;
			esil->cur = num;
			esil->lastsz = bits;
			num = num & bitmask;
			r_write_ble (b, num, R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config), bits);
			ret = r_esil_mem_write (esil, addr, b, bytes);
		}
	}
out:
	free (src2);
	free (src);
	free (dst);
	return ret;
}

static bool esil_poke1(REsil *esil) {
	return esil_poke_n (esil, 8);
}

static bool esil_poke2(REsil *esil) {
	return esil_poke_n (esil, 16);
}

static bool esil_poke3(REsil *esil) {
	return esil_poke_n (esil, 24);
}

static bool esil_poke4(REsil *esil) {
	return esil_poke_n (esil, 32);
}

static bool esil_poke8(REsil *esil) {
	return esil_poke_n (esil, 64);
}

static bool esil_poke16(REsil *esil) {
	return esil_poke_n (esil, 128);
}

static bool esil_poke_some(REsil *esil) {
	bool ret = false;
	int i, regsize;
	ut64 ptr, regs = 0, tmp;
	char *count, *dst = r_esil_pop (esil);

	if (dst && r_esil_get_parm_size (esil, dst, &tmp, &regsize)) {
		// reg
		isregornum (esil, dst, &ptr);
		count = r_esil_pop (esil);
		if (count) {
			isregornum (esil, count, &regs);
			if (regs > 0) {
				ut8 b[8] = {0};
				ut64 num64;
				for (i = 0; i < regs; i++) {
					char *foo = r_esil_pop (esil);
					if (!foo) {
						// avoid looping out of stack
						free (dst);
						free (count);
						return true;
					}
					r_esil_get_parm_size (esil, foo, &tmp, &regsize);
					isregornum (esil, foo, &num64);
					r_write_ble (b, num64, R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config), regsize);
					const int size_bytes = regsize / 8;
					const ut32 written = r_esil_mem_write (esil, ptr, b, size_bytes);
					if (written != size_bytes) {
						//R_LOG_ERROR ("Cannot write at 0x%08" PFMT64x, ptr);
						esil->trap = 1;
					}
					ptr += size_bytes;
					free (foo);
				}
			}
			free (dst);
			free (count);
			return ret;
		}
		free (dst);
	}
	return false;
}

/* PEEK */

static bool esil_peek_n(REsil *esil, int bits) {
	if (bits & 7) {
		return false;
	}
	bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config);
	bool ret = false;
	char res[SDB_NUM_BUFSZ];
	ut64 addr;
	ut32 bytes = bits / 8;
	char *dst = r_esil_pop (esil);
	if (!dst) {
		R_LOG_ERROR ("ESIL failed at 0x%08"PFMT64x": Won't peek the memory unless the users tells that", esil->addr);
		return false;
	}
	//eprintf ("GONA PEEK %d dst:%s\n", bits, dst);
	if (dst && isregornum (esil, dst, &addr)) {
		if (bits == 128) {
			ut8 a[sizeof (ut64) * 2] = {0};
			ret = r_esil_mem_read (esil, addr, a, bytes);
			ut64 b = r_read_ble64 (&a, be);
			ut64 c = r_read_ble64 (&a[8], be);
			sdb_itoa (b, 16, res, sizeof (res));
			r_esil_push (esil, res);
			sdb_itoa (c, 16, res, sizeof (res));
			r_esil_push (esil, res);
			free (dst);
			return ret;
		}
		ut64 bitmask = r_num_genmask (bits - 1);
		ut8 a[sizeof (ut64)] = {0};
		ret = !!r_esil_mem_read (esil, addr, a, bytes);
#if 0
		ut64 b = r_read_ble64 (a, esil->anal->config->big_endian);
#else
		ut64 b = r_read_ble64 (a, 0);
		if (be) {
			r_mem_swapendian ((ut8*)&b, (const ut8*)&b, bytes);
		}
#endif
		sdb_itoa (b & bitmask, 16, res, sizeof (res));
		r_esil_push (esil, res);
		esil->lastsz = bits;
	}
	free (dst);
	return ret;
}

static bool esil_peek1(REsil *esil) {
	return esil_peek_n (esil, 8);
}

static bool esil_peek2(REsil *esil) {
	return esil_peek_n (esil, 16);
}

static bool esil_peek3(REsil *esil) {
	return esil_peek_n (esil, 24);
}

static bool esil_peek4(REsil *esil) {
	return esil_peek_n (esil, 32);
}

static bool esil_peek8(REsil *esil) {
	return esil_peek_n (esil, 64);
}

static bool esil_peek16(REsil *esil) {
	// packed only
	return esil_peek_n (esil, 128);
}

static bool esil_peek_some(REsil *esil) {
	int i;
	ut64 ptr, regs;
	// pop ptr
	char *count, *dst = r_esil_pop (esil);
	if (dst) {
		// reg
		isregornum (esil, dst, &ptr);
		count = r_esil_pop (esil);
		if (count) {
			isregornum (esil, count, &regs);
			if (regs > 0) {
				ut8 a[4];
				for (i = 0; i < regs; i++) {
					char *foo = r_esil_pop (esil);
					if (!foo) {
						R_LOG_DEBUG ("Cannot pop in peek");
						free (dst);
						free (count);
						return false;
					}
					bool oks = r_esil_mem_read (esil, ptr, a, 4);
					if (!oks) {
						if (esil->verbose) {
							R_LOG_ERROR ("Cannot peek from 0x%08" PFMT64x, ptr);
						}
						free (dst);
						free (count);
						return false;
					}
					ut32 num32 = r_read_ble32 (a, R_ARCH_CONFIG_IS_BIG_ENDIAN (esil->anal->config));
					r_esil_reg_write (esil, foo, num32);
					ptr += 4;
					free (foo);
				}
			}
			free (dst);
			free (count);
			return 1;
		}
		free (dst);
	}
	return 0;
}

/* OREQ */

static bool esil_mem_oreq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil); // save the dst-addr
	char *src0 = r_esil_pop (esil); // get the src
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) { 	// get the src
		r_esil_push (esil, dst);			// push the dst-addr
		ret = !!esil_peek_n (esil, bits);		// read
		src1 = r_esil_pop (esil);			// get the old dst-value
		if (src1 && r_esil_get_parm (esil, src1, &d)) { // get the old dst-value
			d |= s;					// calculate the new dst-value
			r_esil_pushnum (esil, d);		// push the new dst-value
			r_esil_push (esil, dst);		// push the dst-addr
			ret &= (!!esil_poke_n (esil, bits));	// write
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_oreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_oreq1(REsil *esil) {
	return esil_mem_oreq_n (esil, 8);
}
static bool esil_mem_oreq2(REsil *esil) {
	return esil_mem_oreq_n (esil, 16);
}
static bool esil_mem_oreq4(REsil *esil) {
	return esil_mem_oreq_n (esil, 32);
}
static bool esil_mem_oreq8(REsil *esil) {
	return esil_mem_oreq_n (esil, 64);
}

/* XOREQ */

static bool esil_mem_xoreq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		r_esil_push (esil, dst);
		ret = !!esil_peek_n (esil, bits);
		src1 = r_esil_pop (esil);
		if (src1 && r_esil_get_parm (esil, src1, &d)) {
			d ^= s;
			r_esil_pushnum (esil, d);
			r_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_xoreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_xoreq1(REsil *esil) {
	return esil_mem_xoreq_n (esil, 8);
}
static bool esil_mem_xoreq2(REsil *esil) {
	return esil_mem_xoreq_n (esil, 16);
}
static bool esil_mem_xoreq4(REsil *esil) {
	return esil_mem_xoreq_n (esil, 32);
}
static bool esil_mem_xoreq8(REsil *esil) {
	return esil_mem_xoreq_n (esil, 64);
}

/* ANDEQ */

static bool esil_mem_andeq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		r_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_esil_pop (esil);
		if (src1 && r_esil_get_parm (esil, src1, &d)) {
			d &= s;
			r_esil_pushnum (esil, d);
			r_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_andeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_andeq1(REsil *esil) {
	return esil_mem_andeq_n (esil, 8);
}

static bool esil_mem_andeq2(REsil *esil) {
	return esil_mem_andeq_n (esil, 16);
}

static bool esil_mem_andeq4(REsil *esil) {
	return esil_mem_andeq_n (esil, 32);
}

static bool esil_mem_andeq8(REsil *esil) {
	return esil_mem_andeq_n (esil, 64);
}

/* ADDEQ */

static bool esil_mem_addeq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		r_esil_push (esil, dst);
		ret = !!esil_peek_n (esil, bits);
		src1 = r_esil_pop (esil);
		if (src1 && r_esil_get_parm (esil, src1, &d)) {
			d += s;
			r_esil_pushnum (esil, d);
			r_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_addeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_addeq1(REsil *esil) {
	return esil_mem_addeq_n (esil, 8);
}
static bool esil_mem_addeq2(REsil *esil) {
	return esil_mem_addeq_n (esil, 16);
}
static bool esil_mem_addeq4(REsil *esil) {
	return esil_mem_addeq_n (esil, 32);
}
static bool esil_mem_addeq8(REsil *esil) {
	return esil_mem_addeq_n (esil, 64);
}

/* SUBEQ */

static bool esil_mem_subeq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		r_esil_push (esil, dst);
		ret = !!esil_peek_n (esil, bits);
		src1 = r_esil_pop (esil);
		if (src1 && r_esil_get_parm (esil, src1, &d)) {
			d -= s;
			r_esil_pushnum (esil, d);
			r_esil_push (esil, dst);
			ret &= !!esil_poke_n (esil, bits);
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_subeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_subeq1(REsil *esil) {
	return esil_mem_subeq_n (esil, 8);
}
static bool esil_mem_subeq2(REsil *esil) {
	return esil_mem_subeq_n (esil, 16);
}
static bool esil_mem_subeq4(REsil *esil) {
	return esil_mem_subeq_n (esil, 32);
}
static bool esil_mem_subeq8(REsil *esil) {
	return esil_mem_subeq_n (esil, 64);
}

/* MODEQ */

static bool esil_mem_modeq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		if (s == 0) {
			R_LOG_DEBUG ("esil_mem_modeq4: Division by zero!");
			esil->trap = R_ANAL_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			r_esil_push (esil, dst);
			ret = !!esil_peek_n (esil, bits);
			src1 = r_esil_pop (esil);
			if (src1 && r_esil_get_parm (esil, src1, &d) && s >= 1) {
				r_esil_pushnum (esil, d % s);
				d = d % s;
				r_esil_pushnum (esil, d);
				r_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_modeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_modeq1(REsil *esil) {
	return esil_mem_modeq_n (esil, 8);
}
static bool esil_mem_modeq2(REsil *esil) {
	return esil_mem_modeq_n (esil, 16);
}
static bool esil_mem_modeq4(REsil *esil) {
	return esil_mem_modeq_n (esil, 32);
}
static bool esil_mem_modeq8(REsil *esil) {
	return esil_mem_modeq_n (esil, 64);
}

/* DIVEQ */

static bool esil_mem_diveq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		if (s == 0) {
			R_LOG_DEBUG ("esil_mem_diveq8: Division by zero!");
			esil->trap = R_ANAL_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			r_esil_push (esil, dst);
			ret = !!esil_peek_n (esil, bits);
			src1 = r_esil_pop (esil);
			if (src1 && r_esil_get_parm (esil, src1, &d)) {
				d = d / s;
				r_esil_pushnum (esil, d);
				r_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_diveq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_diveq1(REsil *esil) {
	return esil_mem_diveq_n (esil, 8);
}
static bool esil_mem_diveq2(REsil *esil) {
	return esil_mem_diveq_n (esil, 16);
}
static bool esil_mem_diveq4(REsil *esil) {
	return esil_mem_diveq_n (esil, 32);
}
static bool esil_mem_diveq8(REsil *esil) {
	return esil_mem_diveq_n (esil, 64);
}

/* MULEQ */

static bool esil_mem_muleq_n(REsil *esil, int bits, ut64 bitmask) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		r_esil_push (esil, dst);
		ret = !!esil_peek_n (esil, bits);
		src1 = r_esil_pop (esil);
		if (src1 && r_esil_get_parm (esil, src1, &d)) {
			d *= s;
			r_esil_pushnum (esil, d);
			r_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_muleq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_muleq1(REsil *esil) {
	return esil_mem_muleq_n (esil, 8, UT8_MAX);
}
static bool esil_mem_muleq2(REsil *esil) {
	return esil_mem_muleq_n (esil, 16, UT16_MAX);
}
static bool esil_mem_muleq4(REsil *esil) {
	return esil_mem_muleq_n (esil, 32, UT32_MAX);
}
static bool esil_mem_muleq8(REsil *esil) {
	return esil_mem_muleq_n (esil, 64, UT64_MAX);
}

/* INCEQ */

static bool esil_mem_inceq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s;
	char *off = r_esil_pop (esil);
	char *src = NULL;
	if (off) {
		r_esil_push (esil, off);
		ret = !!esil_peek_n (esil, bits);
		src = r_esil_pop (esil);
		if (src && r_esil_get_parm (esil, src, &s)) {
			esil->old = s;
			s++;
			esil->cur = s;
			esil->lastsz = bits;
			r_esil_pushnum (esil, s);
			r_esil_push (esil, off);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_inceq_n: invalid parameters");
	}
	free (src);
	free (off);
	return ret;
}

static bool esil_mem_inceq1(REsil *esil) {
	return esil_mem_inceq_n (esil, 8);
}
static bool esil_mem_inceq2(REsil *esil) {
	return esil_mem_inceq_n (esil, 16);
}
static bool esil_mem_inceq4(REsil *esil) {
	return esil_mem_inceq_n (esil, 32);
}
static bool esil_mem_inceq8(REsil *esil) {
	return esil_mem_inceq_n (esil, 64);
}

/* DECEQ */

static bool esil_mem_deceq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s;
	char *off = r_esil_pop (esil);
	char *src = NULL;
	if (off) {
		r_esil_push (esil, off);
		ret = !!esil_peek_n (esil, bits);
		src = r_esil_pop (esil);
		if (src && r_esil_get_parm (esil, src, &s)) {
			s--;
			r_esil_pushnum (esil, s);
			r_esil_push (esil, off);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_deceq_n: invalid parameters");
	}
	free (src);
	free (off);
	return ret;
}

static bool esil_mem_deceq1(REsil *esil) {
	return esil_mem_deceq_n (esil, 8);
}
static bool esil_mem_deceq2(REsil *esil) {
	return esil_mem_deceq_n (esil, 16);
}
static bool esil_mem_deceq4(REsil *esil) {
	return esil_mem_deceq_n (esil, 32);
}
static bool esil_mem_deceq8(REsil *esil) {
	return esil_mem_deceq_n (esil, 64);
}

/* LSLEQ */

static bool esil_mem_lsleq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		if (s > sizeof (ut64) * 8) {
			R_LOG_DEBUG ("esil_mem_lsleq_n: shift is too big");
		} else {
			r_esil_push (esil, dst);
			ret = !!esil_peek_n (esil, bits);
			src1 = r_esil_pop (esil);
			if (src1 && r_esil_get_parm (esil, src1, &d)) {
				if (s > 63) {
					d = 0;
				} else {
					d <<= s;
				}
				r_esil_pushnum (esil, d);
				r_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_lsleq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_lsleq1(REsil *esil) {
	return esil_mem_lsleq_n (esil, 8);
}
static bool esil_mem_lsleq2(REsil *esil) {
	return esil_mem_lsleq_n (esil, 16);
}
static bool esil_mem_lsleq4(REsil *esil) {
	return esil_mem_lsleq_n (esil, 32);
}
static bool esil_mem_lsleq8(REsil *esil) {
	return esil_mem_lsleq_n (esil, 64);
}

/* LSREQ */

static bool esil_mem_lsreq_n(REsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_esil_pop (esil);
	char *src0 = r_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_esil_get_parm (esil, src0, &s)) {
		r_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_esil_pop (esil);
		if (src1 && r_esil_get_parm (esil, src1, &d)) {
			d >>= s;
			r_esil_pushnum (esil, d);
			r_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		R_LOG_DEBUG ("esil_mem_lsreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_lsreq1(REsil *esil) {
	return esil_mem_lsreq_n (esil, 8);
}
static bool esil_mem_lsreq2(REsil *esil) {
	return esil_mem_lsreq_n (esil, 16);
}
static bool esil_mem_lsreq4(REsil *esil) {
	return esil_mem_lsreq_n (esil, 32);
}
static bool esil_mem_lsreq8(REsil *esil) {
	return esil_mem_lsreq_n (esil, 64);
}

/* get value of register or memory reference and push the value */
static bool esil_num(REsil *esil) {
	char *dup_me;
	ut64 dup;
	if (!esil) {
		return false;
	}
	if (!(dup_me = r_esil_pop (esil))) {
		return false;
	}
	if (!r_esil_get_parm (esil, dup_me, &dup)) {
		free (dup_me);
		return false;
	}
	free (dup_me);
	return r_esil_pushnum (esil, dup);
}

/* duplicate the last element in the stack */
static bool esil_dup(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	const int stackptr = esil->stackptr;
	if (!esil->stack || stackptr < 1 || stackptr > (esil->stacksize - 1)) {
		R_LOG_WARN ("Nothing to dup");
		return false;
	}
	const char *ss = esil->stack[stackptr - 1];
	if (ss && *ss) {
		return r_esil_push (esil, ss);
	}
	R_LOG_WARN ("Nothing to dup");
	return false;
}


static bool esil_swap(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	const int stackptr = esil->stackptr;
	if (!esil->stack || stackptr < 2) {
		return false;
	}
	if (!esil->stack[stackptr - 1] || !esil->stack[stackptr - 2]) {
		return false;
	}
	char *tmp = esil->stack[stackptr - 1];
	esil->stack[stackptr - 1] = esil->stack[stackptr - 2];
	esil->stack[stackptr - 2] = tmp;
	return true;
}

static bool esil_smaller(REsil *esil) { // 'dst < src' => 'src,dst,<'
	ut64 num, num2;
	bool ret = false;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			ret = true;
			pushnums (esil, src, num2, dst, num);
			r_esil_pushnum (esil, (num != num2)
					& !signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_bigger(REsil *esil) { // 'dst > src' => 'src,dst,>'
	ut64 num, num2;
	bool ret = false;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			ret = true;
			pushnums (esil, src, num2, dst, num);
			r_esil_pushnum (esil, signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_smaller_equal(REsil *esil) { // 'dst <= src' => 'src,dst,<='
	ut64 num, num2;
	bool ret = false;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			ret = true;
			pushnums (esil, src, num2, dst, num);
			r_esil_pushnum (esil, !signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_bigger_equal(REsil *esil) { // 'dst >= src' => 'src,dst,>='
	ut64 num, num2;
	bool ret = false;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);
	if (dst && r_esil_get_parm (esil, dst, &num)) {
		if (src && r_esil_get_parm (esil, src, &num2)) {
			pushnums (esil, src, num2, dst, num);
			ret = true;
			r_esil_pushnum (esil, (num == num2)
					| signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_set_jump_target(REsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		esil->jump_target = s;
		esil->jump_target_set = 1;
		ret = true;
	} else {
		R_LOG_DEBUG ("esil_set_jump_target: empty stack");
	}
	free (src);
	return ret;
}

static bool esil_set_jump_target_set(REsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		esil->jump_target_set = s;
		ret = true;
	} else {
		R_LOG_DEBUG ("esil_set_jump_target_set: empty stack");
	}
	free (src);
	return ret;
}

static bool esil_set_delay_slot(REsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_esil_pop (esil);
	if (src && r_esil_get_parm (esil, src, &s)) {
		esil->delay = s;
		ret = true;
	} else {
		R_LOG_DEBUG ("esil_set_delay_slot: empty stack");
	}
	free (src);
	return ret;
}

static int esil_get_parm_float(REsil *esil, const char *str, double *num) {
	return r_esil_get_parm (esil, str, (ut64 *)num);
}

static bool esil_pushnum_float(REsil *esil, double num) {
	RNumFloat n;
	n.f64 = num;
	return r_esil_pushnum (esil, n.u64);
}

static bool esil_is_nan(REsil *esil) {
	bool ret = false;
	double s;
	char *src = r_esil_pop (esil);
	if (src) {
		if (esil_get_parm_float (esil, src, &s)) {
			ret = r_esil_pushnum (esil, isnan (s));
		} else {
			R_LOG_DEBUG ("esil_is_nan: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_is_nan: fail to get argument from stack");
	}
	return ret;
}

static bool esil_int_to_double(REsil *esil, int sign) {
	bool ret = false;
	RNumFloat s;
	char *src = r_esil_pop (esil);
	if (src) {
		if (r_esil_get_parm (esil, src, &s.u64)) {
			ret = (sign)
				? esil_pushnum_float (esil, (double)(s.s64) * 1.0)
				: esil_pushnum_float (esil, (double)(s.u64) * 1.0);
		} else {
			R_LOG_DEBUG ("esil_int_to_float: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_int_to_float: fail to get argument from stack");
	}
	return ret;
}

static bool esil_signed_to_double(REsil *esil) {
	return esil_int_to_double(esil, 1);
}

static bool esil_unsigned_to_double(REsil *esil) {
	return esil_int_to_double (esil, 0);
}

static bool esil_double_to_int(REsil *esil) {
	bool ret = false;
	RNumFloat s;
	char *src = r_esil_pop (esil);
	if (src) {
		if (esil_get_parm_float (esil, src, &s.f64)) {
			if (isnan (s.f64) || isinf (s.f64)) {
				R_LOG_DEBUG ("esil_float_to_int: nan or inf detected");
			}
			if (s.f64 > (double)ST64_MIN && s.f64 < (double)ST64_MAX) {
				ret = r_esil_pushnum (esil, (st64)(s.f64));
			} else {
				R_LOG_DEBUG ("double-to-int out of range");
				ret = r_esil_pushnum (esil, 0);
			}
		} else {
			R_LOG_DEBUG ("esil_float_to_int: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_float_to_int: fail to get argument from stack");
	}
	return ret;
}

static bool esil_double_to_float(REsil *esil) {
	bool ret = false;
	RNumFloat d;
	RNumFloat f;
	ut64 s = 0;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (r_esil_get_parm (esil, src, &s) && esil_get_parm_float (esil, dst, &d.f64)) {
		if (isnan (d.f64) || isinf (d.f64)) {
			ret = r_esil_pushnum (esil, d.u64);
		} else if (s == 32) {
			f.f32 = (float)d.f64;
			ret = r_esil_pushnum (esil, f.u32);
		} else if (s == 64) {
			ret = r_esil_pushnum (esil, d.u64);
		} else if (s == 80 || s == 96 || s == 128 || s == 256) {
			RCFloatProfile profile;
			if (r_cfloat_profile_from_bits (s, &profile)) {
				profile.big_endian = false;
				RCFloatValue fval;
				r_cfloat_value_from_double (&fval, d.f64, &profile);
				ret = r_esil_pushnum (esil, fval.words[0]);
			} else {
				ret = r_esil_pushnum (esil, d.u64);
			}
		} else {
			ret = r_esil_pushnum (esil, d.u64);
		}
	} else {
		R_LOG_DEBUG ("esil_float_to_float: invalid parameters");
	}

	free (dst);
	free (src);
	return ret;
}

static bool esil_float_to_double(REsil *esil) {
	bool ret = false;
	RNumFloat d;
	ut64 s = 0;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (r_esil_get_parm (esil, src, &s) && esil_get_parm_float (esil, dst, &d.f64)) {
		if (isnan (d.f64) || isinf (d.f64)) {
			ret = esil_pushnum_float (esil, d.f64);
		} else if (s == 32) {
			ret = esil_pushnum_float (esil, (double)d.f32);
		} else if (s == 64) {
			ret = esil_pushnum_float (esil, d.f64);
		} else if (s == 80 || s == 96 || s == 128 || s == 256) {
			RCFloatProfile profile;
			if (r_cfloat_profile_from_bits (s, &profile)) {
				profile.big_endian = false;
				RCFloatValue fval = {{0}};
				fval.words[0] = d.u64;
				double result = r_cfloat_value_to_double (&fval, &profile);
				ret = esil_pushnum_float (esil, result);
			} else {
				ret = esil_pushnum_float (esil, d.f64);
			}
		} else {
			ret = esil_pushnum_float (esil, d.f64);
		}
	} else {
		R_LOG_DEBUG ("esil_float_to_float: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_cmp(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (src && dst && esil_get_parm_float (esil, src, &s) && esil_get_parm_float (esil, dst, &d)) {
		if (isnan (s) || isnan (d)) {
			ret = r_esil_pushnum (esil, 0);
		} else {
			ret = r_esil_pushnum (esil, fabs (s - d) <= DBL_EPSILON);
		}
	} else {
		R_LOG_DEBUG ("esil_float_cmp: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_negcmp(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (src && dst && esil_get_parm_float (esil, src, &s) && esil_get_parm_float (esil, dst, &d)) {
		if (isnan (s) || isnan (d)) {
			ret = r_esil_pushnum (esil, 0);
		} else {
			ret = r_esil_pushnum (esil, fabs (s - d) >= DBL_EPSILON);
		}
	} else {
		R_LOG_DEBUG ("esil_float_negcmp: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_less(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (esil_get_parm_float (esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan (s) || isnan (d)) {
			ret = r_esil_pushnum (esil, 0);
		} else {
			ret = r_esil_pushnum (esil, d < s);
		}
	} else {
		R_LOG_DEBUG ("esil_float_less: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_lesseq(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (esil_get_parm_float (esil, src, &s) && esil_get_parm_float (esil, dst, &d)) {
		if (isnan (s) || isnan (d)) {
			ret = r_esil_pushnum (esil, 0);
		} else {
			ret = r_esil_pushnum (esil, d <= s);
		}
	} else {
		R_LOG_DEBUG ("esil_float_lesseq: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_add(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan (s)) {
			ret = esil_pushnum_float (esil, s);
		} else if (isnan (d)) {
			ret = esil_pushnum_float (esil, d);
		} else {
			feclearexcept (FE_OVERFLOW);
			double tmp = s + d;
			(void)(tmp); // suppress unused warning
			int raised = fetestexcept (FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float (esil, NAN);
			} else {
				ret = esil_pushnum_float (esil, s + d);
			}
		}
	} else {
		R_LOG_DEBUG ("esil_float_add: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_sub(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (esil_get_parm_float (esil, src, &s) && esil_get_parm_float (esil, dst, &d)) {
		if (isnan (s)) {
			ret = esil_pushnum_float (esil, s);
		} else if (isnan (d)) {
			ret = esil_pushnum_float (esil, d);
		} else {
			feclearexcept (FE_OVERFLOW);
			double tmp = d - s;
			(void)(tmp);
			int raised = fetestexcept (FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float (esil, NAN);
			} else {
				ret = esil_pushnum_float (esil, d - s);
			}
		}
	} else {
		R_LOG_DEBUG ("esil_float_sub: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_mul(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan (s)) {
			ret = esil_pushnum_float (esil, s);
		} else if (isnan (d)) {
			ret = esil_pushnum_float (esil, d);
		} else {
			feclearexcept (FE_OVERFLOW);
			double tmp = s * d;
			(void)(tmp);
			int raised = fetestexcept (FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float (esil, NAN);
			} else {
				ret = esil_pushnum_float (esil, s * d);
			}
		}
	} else {
		R_LOG_DEBUG ("esil_float_mul: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_div(REsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_esil_pop (esil);
	char *src = r_esil_pop (esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan (s)) {
			ret = esil_pushnum_float (esil, s);
		} else if (isnan (d)) {
			ret = esil_pushnum_float (esil, d);
		} else {
			feclearexcept (FE_OVERFLOW);
			double tmp = d / s;
			(void)(tmp);
			int raised = fetestexcept (FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float (esil, NAN);
			} else {
				ret = esil_pushnum_float (esil, d / s);
			}
		}
	} else {
		R_LOG_DEBUG ("esil_float_div: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_float_neg(REsil *esil) {
	bool ret = false;
	double s;
	char *src = r_esil_pop (esil);
	if (src) {
		if (esil_get_parm_float (esil, src, &s)) {
			ret = esil_pushnum_float (esil, -s);
		} else {
			R_LOG_DEBUG ("esil_float_neg: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_float_neg: fail to get element from stack");
	}
	return ret;
}

static bool esil_float_ceil(REsil *esil) {
	bool ret = false;
	double s;
	char *src = r_esil_pop (esil);

	if (src) {
		if (esil_get_parm_float (esil, src, &s)) {
			if (isnan (s)) {
				ret = esil_pushnum_float (esil, s);
			} else {
				ret = esil_pushnum_float (esil, ceil(s));
			}
		} else {
			R_LOG_DEBUG ("esil_float_ceil: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_float_ceil: fail to get element from stack");
	}
	return ret;
}

static bool esil_float_floor(REsil *esil) {
	bool ret = false;
	double s;
	char *src = r_esil_pop (esil);

	if (src) {
		if (esil_get_parm_float (esil, src, &s)) {
			if (isnan (s)) {
				ret = esil_pushnum_float (esil, s);
			} else {
				ret = esil_pushnum_float (esil, floor(s));
			}
		} else {
			R_LOG_DEBUG ("esil_float_floor: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_float_floor: fail to get element from stack");
	}

	return ret;
}

static bool esil_float_round(REsil *esil) {
	bool ret = false;
	double s;
	char *src = r_esil_pop (esil);

	if (src) {
		if (esil_get_parm_float (esil, src, &s)) {
			if (isnan (s)) {
				ret = esil_pushnum_float (esil, s);
			} else {
				ret = esil_pushnum_float (esil, round(s));
			}
		} else {
			R_LOG_DEBUG ("esil_float_round: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_float_round: fail to get element from stack");
	}
	return ret;
}

static bool esil_float_sqrt(REsil *esil) {
	bool ret = false;
	double s;
	char *src = r_esil_pop (esil);

	if (src) {
		if (esil_get_parm_float (esil, src, &s)) {
			if (isnan (s)) {
				ret = esil_pushnum_float (esil, s);
			} else {
				ret = esil_pushnum_float (esil, sqrt (s));
			}
		} else {
			R_LOG_DEBUG ("esil_float_sqrt: invalid parameters");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("esil_float_sqrt: fail to get element from stack");
	}
	return ret;
}

R_API bool r_esil_setup_ops(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	bool ret = OP ("$", esil_interrupt, 0, 1, OT_UNK); // hm, type seems a bit wrong
	ret &= OP ("#!", esil_cmd, 0, 1, OT_UNK); // hm, type seems a bit wrong
	ret &= OP ("()", esil_syscall, 0, 1, OT_UNK);
	ret &= OP ("$z", esil_zf, 1, 0, OT_UNK); // add OT_FLAG
	ret &= OP ("$c", esil_cf, 1, 1, OT_UNK);
	ret &= OP ("$b", esil_bf, 1, 1, OT_UNK);
	ret &= OP ("$p", esil_pf, 1, 0, OT_UNK);
	ret &= OP ("$s", esil_sf, 1, 1, OT_UNK);
	ret &= OP ("$o", esil_of, 1, 1, OT_UNK);
	ret &= OP ("$ds", esil_ds, 1, 0, OT_UNK);
	ret &= OP ("$jt", esil_jt, 1, 0, OT_UNK);
	ret &= OP ("$js", esil_js, 1, 0, OT_UNK);
	ret &= OP ("r=", esil_regalias, 1, 0, OT_UNK); // r0,PC,@= -> change PC alias to r0
	ret &= OP ("~", esil_signext, 1, 2, OT_MATH);
	ret &= OP ("~=", esil_signexteq, 0, 2, OT_MATH);
	ret &= OP ("==", esil_cmp, 0, 2, OT_MATH);
	ret &= OP ("<", esil_smaller, 1, 2, OT_MATH);
	ret &= OP (">", esil_bigger, 1, 2, OT_MATH);
	ret &= OP ("<=", esil_smaller_equal, 1, 2, OT_MATH);
	ret &= OP (">=", esil_bigger_equal, 1, 2, OT_MATH);
	ret &= OP ("?{", esil_if, 0, 1, OT_CTR);
	ret &= OP ("<<", esil_lsl, 1, 2, OT_MATH);
	ret &= OP ("LSL", esil_lsl, 1, 2, OT_MATH);
	ret &= OP ("<<=", esil_lsleq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("LSL=", esil_lsleq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP (">>", esil_lsr, 1, 2, OT_MATH);
	ret &= OP ("LSR", esil_lsr, 1, 2, OT_MATH);
	ret &= OP (">>=", esil_lsreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("LSR=", esil_lsreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP (">>>>", esil_asr, 1, 2, OT_MATH);
	ret &= OP ("ASR", esil_asr, 1, 2, OT_MATH);
	ret &= OP (">>>>=", esil_asreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("ASR=", esil_asreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP (">>>", esil_ror, 1, 2, OT_MATH);
	ret &= OP ("ROR", esil_ror, 1, 2, OT_MATH);
	ret &= OP (">>>=", esil_roreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("ROR=", esil_roreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("<<<", esil_rol, 1, 2, OT_MATH);
	ret &= OP ("ROL", esil_rol, 1, 2, OT_MATH);
	ret &= OP ("<<<=", esil_roleq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("ROL=", esil_roleq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("&", esil_and, 1, 2, OT_MATH);
	ret &= OP ("&=", esil_andeq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("}", esil_nop, 0, 0, OT_CTR); // just to avoid push
	ret &= OP ("}{", esil_nop, 0, 0, OT_CTR);
	ret &= OP ("|", esil_or, 1, 2, OT_MATH);
	ret &= OP ("|=", esil_oreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("!", esil_neg, 1, 1, OT_MATH);
	ret &= OP ("!=", esil_negeq, 0, 1, OT_MATH | OT_REGW);
	ret &= OP ("=", esil_eq, 0, 2, OT_REGW);
	ret &= OP (":=", esil_weak_eq, 0, 2, OT_REGW);
	ret &= OP ("L*", esil_long_mul, 2, 2, OT_MATH);
	ret &= OP ("*", esil_mul, 1, 2, OT_MATH);
	ret &= OP ("*=", esil_muleq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("^", esil_xor, 1, 2, OT_MATH);
	ret &= OP ("^=", esil_xoreq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("+", esil_add, 1, 2, OT_MATH);
	ret &= OP ("+=", esil_addeq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("++", esil_inc, 0, 1, OT_MATH | OT_REGW);
	ret &= OP ("++=", esil_inceq, 0, 1, OT_MATH | OT_REGW);
	ret &= OP ("-", esil_sub, 1, 2, OT_MATH);
	ret &= OP ("-=", esil_subeq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("--", esil_dec, 1, 1, OT_MATH);
	ret &= OP ("--=", esil_deceq, 0, 1, OT_MATH | OT_REGW);
	ret &= OP ("/", esil_div, 1, 2, OT_MATH);
	ret &= OP ("~/", esil_signed_div, 1, 2, OT_MATH);
	ret &= OP ("/=", esil_diveq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("%", esil_mod, 1, 2, OT_MATH);
	ret &= OP ("~%", esil_signed_mod, 1, 2, OT_MATH);
	ret &= OP ("%=", esil_modeq, 0, 2, OT_MATH | OT_REGW);
	ret &= OP ("=[1]", esil_poke1, 0, 2, OT_MEMW);
	ret &= OP ("=[2]", esil_poke2, 0, 2, OT_MEMW);
	ret &= OP ("=[3]", esil_poke3, 0, 2, OT_MEMW);
	ret &= OP ("=[4]", esil_poke4, 0, 2, OT_MEMW);
	ret &= OP ("=[8]", esil_poke8, 0, 2, OT_MEMW);
	ret &= OP ("=[16]", esil_poke16, 0, 2, OT_MEMW);
	ret &= OP ("|=[1]", esil_mem_oreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("|=[2]", esil_mem_oreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("|=[4]", esil_mem_oreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("|=[8]", esil_mem_oreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("^=[1]", esil_mem_xoreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("^=[2]", esil_mem_xoreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("^=[4]", esil_mem_xoreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("^=[8]", esil_mem_xoreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("&=[1]", esil_mem_andeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("&=[2]", esil_mem_andeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("&=[4]", esil_mem_andeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("&=[8]", esil_mem_andeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("+=[1]", esil_mem_addeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("+=[2]", esil_mem_addeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("+=[4]", esil_mem_addeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("+=[8]", esil_mem_addeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("-=[1]", esil_mem_subeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("-=[2]", esil_mem_subeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("-=[4]", esil_mem_subeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("-=[8]", esil_mem_subeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("%=[1]", esil_mem_modeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("%=[2]", esil_mem_modeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("%=[4]", esil_mem_modeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("%=[8]", esil_mem_modeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("/=[1]", esil_mem_diveq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("/=[2]", esil_mem_diveq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("/=[4]", esil_mem_diveq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("/=[8]", esil_mem_diveq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("*=[1]", esil_mem_muleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("*=[2]", esil_mem_muleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("*=[4]", esil_mem_muleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("*=[8]", esil_mem_muleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("++=[1]", esil_mem_inceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("++=[2]", esil_mem_inceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("++=[4]", esil_mem_inceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("++=[8]", esil_mem_inceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("--=[1]", esil_mem_deceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("--=[2]", esil_mem_deceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("--=[4]", esil_mem_deceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("--=[8]", esil_mem_deceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("<<=[1]", esil_mem_lsleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("<<=[2]", esil_mem_lsleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("<<=[4]", esil_mem_lsleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("<<=[8]", esil_mem_lsleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP (">>=[1]", esil_mem_lsreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP (">>=[2]", esil_mem_lsreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP (">>=[4]", esil_mem_lsreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP (">>=[8]", esil_mem_lsreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	ret &= OP ("[*]", esil_peek_some, 0, 0, OT_MEMR);
	ret &= OP ("=[*]", esil_poke_some, 0, 0, OT_MEMW);
	ret &= OP2 ("[1]", esil_peek1, 1, 1, OT_MEMR, "read 1 byte from address taken from stack push the byte value");
	ret &= OP ("[2]", esil_peek2, 1, 1, OT_MEMR);
	ret &= OP ("[3]", esil_peek3, 1, 1, OT_MEMR);
	ret &= OP ("[4]", esil_peek4, 1, 1, OT_MEMR);
	ret &= OP ("[8]", esil_peek8, 1, 1, OT_MEMR);
	ret &= OP ("[16]", esil_peek16, 1, 1, OT_MEMR);
	ret &= OP ("STACK", r_esil_dumpstack, 0, 0, OT_UNK);
	ret &= OP ("POP", esil_pop, 0, 1, OT_UNK);
	ret &= OP ("TODO", esil_todo, 0, 0, OT_UNK);
	ret &= OP ("GOTO", esil_goto, 0, 1, OT_CTR);
	ret &= OP ("BREAK", esil_break, 0, 0, OT_CTR);
	ret &= OP ("CLEAR", esil_clear, 0, 0, OT_UNK);
	ret &= OP ("DUP", esil_dup, 2, 1, OT_UNK);
	ret &= OP ("NUM", esil_num, 1, 1, OT_UNK);
	ret &= OP ("SWAP", esil_swap, 2, 2, OT_UNK);
	ret &= OP ("TRAP", esil_trap, 0, 2, OT_UNK); // syscall?
	ret &= OP ("BITS", esil_bits, 1, 0, OT_UNK);
	ret &= OP ("SETJT", esil_set_jump_target, 0, 1, OT_UNK);
	ret &= OP ("SETJTS", esil_set_jump_target_set, 0, 1, OT_UNK);
	ret &= OP ("SETD", esil_set_delay_slot, 0, 1, OT_UNK);

	/* we all float down here */
	ret &= OP2 ("NAN", esil_is_nan, 1, 1, OT_MATH, "check if not a number, returns 1|0");
	// XXX I2D and S2D do the same, kill one
	ret &= OP ("I2D", esil_signed_to_double, 1, 1, OT_MATH);
	// OP ("S2D", esil_signed_to_double, 1, 1, OT_MATH); R_DEPRECATE
	ret &= OP ("U2D", esil_unsigned_to_double, 1, 1, OT_MATH);
	ret &= OP ("D2I", esil_double_to_int, 1, 1, OT_MATH);
	ret &= OP ("D2F", esil_double_to_float, 1, 2, OT_MATH);
	ret &= OP ("F2D", esil_float_to_double, 1, 2, OT_MATH);
	ret &= OP ("F==", esil_float_cmp, 1, 2, OT_MATH);
	ret &= OP ("F!=", esil_float_negcmp, 1, 2, OT_MATH); // DEPRECATE
	ret &= OP ("F<", esil_float_less, 1, 2, OT_MATH);
	ret &= OP ("F<=", esil_float_lesseq, 1, 2, OT_MATH);
	ret &= OP ("F+", esil_float_add, 1, 2, OT_MATH);
	ret &= OP ("F-", esil_float_sub, 1, 2, OT_MATH);
	ret &= OP ("F*", esil_float_mul, 1, 2, OT_MATH);
	ret &= OP ("F/", esil_float_div, 1, 2, OT_MATH);
	ret &= OP ("-F", esil_float_neg, 1, 1, OT_MATH);
	ret &= OP ("CEIL", esil_float_ceil, 1, 1, OT_MATH);
	ret &= OP ("FLOOR", esil_float_floor, 1, 1, OT_MATH);
	ret &= OP ("ROUND", esil_float_round, 1, 1, OT_MATH);
	return ret & OP ("SQRT", esil_float_sqrt, 1, 1, OT_MATH);
}

typedef struct {
	RStrBuf *sb;
	PJ *pj;
} OpsData;

static bool opsforeach(void *user, const void *key, const void *value) {
	OpsData *opsdata = (OpsData*)user;
	REsilOp *eop = (REsilOp*)value;
	const char *type = "";
	switch (eop->type) {
	case OT_MATH: type = " (math)"; break;
	case OT_UNK: type = " (unknown)"; break;
	case OT_CTR: type = " (control)"; break;
	case OT_MATH|OT_REGW: type = " (math+regw)"; break;
	case OT_MATH|OT_MEMR|OT_REGW: type = " (math+memr+regw)"; break;
	case OT_MEMR: type = " (memr)"; break;
	case OT_MEMW: type = " (memw)"; break;
	}
	if (opsdata->sb) {
		r_strbuf_appendf (opsdata->sb, ": %s (%d -- %d) \\ %s%s\n",
			(const char *)key, eop->pop, eop->push, eop->info?eop->info: "", type);
	} else if (opsdata->pj) {
		PJ *pj = opsdata->pj;
		pj_o (pj);
		pj_ks (pj, "name", key);
		pj_kn (pj, "inputs", eop->pop);
		pj_kn (pj, "outputs", eop->push);
		if (eop->info) {
			pj_ks (pj, "info", eop->info);
		}
		if (R_STR_ISNOTEMPTY (type)) {
			pj_ks (pj, "type", type);
		}
		pj_end (pj);
	}
	return true;
}

R_API char *r_esil_opstr(REsil *esil, int mode) {
	OpsData opsdata = { 0 };
	if (mode == 'j') {
		opsdata.pj = pj_new ();
		pj_a (opsdata.pj);
	} else {
		opsdata.sb = r_strbuf_new ("");
	}
	ht_pp_foreach (esil->ops, opsforeach, &opsdata);
	if (mode == 'j') {
		pj_end (opsdata.pj);
		return pj_drain (opsdata.pj);
	}
	return r_strbuf_drain (opsdata.sb);
}
