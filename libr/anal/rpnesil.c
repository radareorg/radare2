/* radare - LGPL - Copyright 2014 - pancake */

#include <r_anal.h>
#include <r_types.h>
#include <r_util.h>
#include <r_db.h>

#define FLG(x) R_ANAL_ESIL_FLAG_##x
#define cpuflag(x,y) if (y) { R_BIT_SET (&esil->flags, FLG(x)); } else { R_BIT_UNSET (&esil->flags, FLG(x)); }
static int esil_reg_write (RAnalEsil *esil, const char *dst, ut64 num);
static int esil_reg_read (RAnalEsil *esil, const char *regname, ut64 *num);

const ut64 masks[] = {
	0x0000000000000001,
	0x0000000000000003,
	0x0000000000000007,
	0x000000000000000f,
	0x000000000000001f,
	0x000000000000003f,
	0x000000000000007f,
	0x00000000000000ff,
	0x00000000000001ff,
	0x00000000000003ff,
	0x00000000000007ff,
	0x0000000000000fff,
	0x0000000000001fff,
	0x0000000000003fff,
	0x0000000000007fff,
	0x000000000000ffff,
	0x000000000001ffff,
	0x000000000003ffff,
	0x000000000007ffff,
	0x00000000000fffff,
	0x00000000001fffff,
	0x00000000003fffff,
	0x00000000007fffff,
	0x0000000000ffffff,
	0x0000000001ffffff,
	0x0000000003ffffff,
	0x0000000007ffffff,
	0x000000000fffffff,
	0x000000001fffffff,
	0x000000003fffffff,
	0x000000007fffffff,
	0x00000000ffffffff,
	0x00000001ffffffff,
	0x00000003ffffffff,
	0x00000007ffffffff,
	0x0000000fffffffff,
	0x0000001fffffffff,
	0x0000003fffffffff,
	0x0000007fffffffff,
	0x000000ffffffffff,
	0x000001ffffffffff,
	0x000003ffffffffff,
	0x000007ffffffffff,
	0x00000fffffffffff,
	0x00001fffffffffff,
	0x00003fffffffffff,
	0x00007fffffffffff,
	0x0000ffffffffffff,
	0x0001ffffffffffff,
	0x0003ffffffffffff,
	0x0007ffffffffffff,
	0x000fffffffffffff,
	0x001fffffffffffff,
	0x003fffffffffffff,
	0x007fffffffffffff,
	0x00ffffffffffffff,
	0x01ffffffffffffff,
	0x03ffffffffffffff,
	0x07ffffffffffffff,
	0x0fffffffffffffff,
	0x1fffffffffffffff,
	0x3fffffffffffffff,
	0x7fffffffffffffff,
	0xffffffffffffffff
};

R_API RAnalEsil *r_anal_esil_new() {
	RAnalEsil *esil = R_NEW0 (RAnalEsil);
	esil->ops = sdb_new0 ();
	return esil;
}

R_API int r_anal_esil_set_op (RAnalEsil *esil, const char *op, RAnalEsilOp code) {
	char t[128];
	char *h;
	if (!code || !op || !strlen(op) || !esil || !esil->ops) {
		return R_FALSE;
	}
	h = sdb_itoa (sdb_hash (op), t, 16);
	sdb_num_set (esil->ops, h, (ut64)code, 0);
	if (!sdb_num_exists (esil->ops, h))
		eprintf ("can't set esil-op %s\n", op);
	return R_TRUE;
}

R_API void r_anal_esil_free (RAnalEsil *esil) {
	int i;
	for (i=0; i<esil->stackptr;i++)
		free (esil->stack[i]);
	if (esil->ops)
		sdb_free (esil->ops);
	if (esil->anal && esil->anal->cur && esil->anal->cur->esil_init && esil->anal->cur->esil_fini)
		esil->anal->cur->esil_fini (esil);
	free (esil);
}

static int internal_esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	if (!esil || !esil->anal || !esil->anal->iob.io)
		return 0;
	return esil->anal->iob.read_at (esil->anal->iob.io, addr, buf, len);
}

static int esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	int i, ret = 0;
	if (!buf || !esil)
		return 0;
	if (esil->hook_mem_read) {
		ret = esil->hook_mem_read (esil, addr, buf, len);
	}
	if (!ret && esil->mem_read) {
		ret = esil->mem_read (esil, addr, buf, len);
	}
	if (esil->debug) {
		eprintf ("0x%08"PFMT64x" R> ", addr);
		for (i=0;i<len;i++)
			eprintf ("%02x", buf[i]);
		eprintf ("\n");
	}
	return ret;
}

static int internal_esil_mem_write (ESIL *esil, ut64 addr, const ut8 *buf, int len) {
	if (!esil || !esil->anal || !esil->anal->iob.io)
		return 0;
	return esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len);
}

static int esil_mem_write (ESIL *esil, ut64 addr, const ut8 *buf, int len) {
	int i, ret = 0;
	if (!buf || !esil)
		return 0;
	if (esil->debug) {
		eprintf ("0x%08"PFMT64x" <W ", addr);
		for (i=0;i<len;i++)
			eprintf ("%02x", buf[i]);
		eprintf ("\n");
	}
	if (esil->hook_mem_write) {
		ret = esil->hook_mem_write (esil, addr, buf, len);
	}
	if (!ret && esil->mem_write) {
		ret = esil->mem_write (esil, addr, buf, len);
	}
	return ret;
}

static int internal_esil_reg_read(RAnalEsil *esil, const char *regname, ut64 *num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (num)
			*num = r_reg_get_value (esil->anal->reg, reg);
		return 1;
	}
	return 0;
}

static int internal_esil_reg_write(RAnalEsil *esil, const char *regname, ut64 num) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		r_reg_set_value (esil->anal->reg, reg, num);
		return 1;
	}
	return 0;
}

static int esil_internal_borrow_check (RAnalEsil *esil, ut8 bit) {
	bit = ((bit & 0x3f) + 0x3e) & 0x3f;	//safer-sex version of -1
	return ((esil->old & masks[bit]) < (esil->cur & masks[bit]));
}

static int esil_internal_carry_check (RAnalEsil *esil, ut8 bit) {
	bit &= 0x3f;				//say no to segfaults
	return ((esil->cur & masks[bit]) < (esil->old & masks[bit]));
}

R_API int r_anal_esil_pushnum(RAnalEsil *esil, ut64 num) {
	char str[64];
	snprintf (str, sizeof (str)-1, "0x%"PFMT64x, num);
	return r_anal_esil_push (esil, str);
}

R_API int r_anal_esil_push(RAnalEsil *esil, const char *str) {
	if (!str || !esil || !*str || esil->stackptr>30)
		return 0;
	esil->stack[esil->stackptr++] = strdup (str);
	return 1;
}

R_API char *r_anal_esil_pop(RAnalEsil *esil) {
	if (esil->stackptr<1)
		return NULL;
	return esil->stack[--esil->stackptr];
}

static int esil_get_parm_type (RAnalEsil *esil, const char *str) {
	int len, i;
	if (!str || !(len=strlen(str)))
		return R_ANAL_ESIL_PARM_INVALID;
	if (str[0] == ESIL_INTERNAL_PREFIX) {
		if (len > 1)
			return R_ANAL_ESIL_PARM_INTERNAL;
		return R_ANAL_ESIL_PARM_INVALID;
	}
	for (i = 0; i < len; i++)
		if (!(str[i] >= '0' && str[i] <= '9'))
			goto not_a_number;
	return R_ANAL_ESIL_PARM_NUM;
	not_a_number:
	if (r_reg_get (esil->anal->reg, str, -1))
		return R_ANAL_ESIL_PARM_REG;
	return R_ANAL_ESIL_PARM_INVALID;
}

static int esil_get_parm (RAnalEsil *esil, const char *str, ut64 *num) {
	int parm_type;
	ut8 bit;
	if (!num)
		return R_FALSE;
	parm_type = esil_get_parm_type (esil, str);
	switch (parm_type) {
		case R_ANAL_ESIL_PARM_INTERNAL:
			switch (str[1]) {
				case 'z':						//zero-flag
					*num = (esil->cur == 0);
					return R_TRUE;
				case 'b':						//borrow
					bit = (ut8) r_num_get (NULL, &str[2]);
					*num = esil_internal_borrow_check (esil, bit);
					return R_TRUE;
				case 'c':						//carry
					bit = (ut8) r_num_get (NULL, &str[2]);
					*num = esil_internal_carry_check (esil, bit);
					return R_TRUE;
				//case 'o':						//overflow
				//case 'p':						//parity
			}
			break;
		case R_ANAL_ESIL_PARM_NUM:
			*num = r_num_get (NULL, str);
			return R_TRUE;
		case R_ANAL_ESIL_PARM_REG:
			esil_reg_read (esil, str, num);
			return R_TRUE;
	}
	return R_FALSE;
}

static int isnum (RAnalEsil *esil, const char *str, ut64 *num) {
	if (*str >= '0' && *str <= '9') {
		if (num)
			*num = r_num_get (NULL, str);
		return 1;
	}
	if (num)
		*num = 0;
	return 0;
}

static int isregornum(RAnalEsil *esil, const char *str, ut64 *num) {
	if (!esil_reg_read (esil, str, num))
		if (!isnum (esil, str, num))
			return 0;
	return 1;
}

static int esil_reg_write (RAnalEsil *esil, const char *dst, ut64 num) {
	int ret = 0;
	if (esil->debug) {
		eprintf ("%s=0x%"PFMT64x"\n", dst, num);
	}
	if (esil->hook_reg_write) {
		ret = esil->hook_reg_write (esil, dst, num);
		if (!ret)
			return ret;
	}
	if (esil->reg_write) {
		return esil->reg_write (esil, dst, num);
	}
	return ret;
}

static int esil_reg_read (RAnalEsil *esil, const char *regname, ut64 *num) {
	int ret = 0;
	if (num)
		*num = 0LL;
	if (esil->hook_reg_read) {
		ret = esil->hook_reg_read (esil, regname, num);
	}
	if (!ret && esil->reg_read) {
		ret = esil->reg_read (esil, regname, num);
	}
	if (ret && num && esil->debug) {
		eprintf ("%s=0x%"PFMT64x"\n", regname, *num);
	}
	return ret;
}

static int esil_eq (RAnalEsil *esil) {
	int ret = 0;
	ut64 num;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && dst && esil_reg_read (esil, dst, NULL)) {
		if (esil_get_parm (esil, src, &num)) {
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)		//necessary for some flag-things
				esil->cur = num;
			esil_reg_read (esil, dst, &num);
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = num;
			ret = esil_reg_write (esil, dst, esil->cur);
		} else eprintf ("esil_eq: invalid src\n");
	} else {
		eprintf ("esil_eq: invalid parameters\n");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_neg(RAnalEsil *esil) {
	int ret = 0;
	ut64 num;
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &num)) {
		num = !num;
		r_anal_esil_pushnum (esil, num);
		ret = 1;
	} else {
		eprintf ("esil_neg: empty stack\n");
	}
	free (src);
	return ret;
}

static int esil_negeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num;
	char *src = r_anal_esil_pop (esil);
	if (src && esil_reg_read (esil, src, &num)) {
		num = !num;
		esil_reg_write (esil, src, num);
		ret = 1;
	} else {
		eprintf ("esil_negeq: empty stack\n");
	}
	free (src);
	return ret;
}

static int esil_andeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = num;
			num &= num2;
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = num;
			esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			eprintf ("esil_andeq: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_oreq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = num;
			num |= num2;
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = num;
			esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			eprintf ("esil_andeq: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_xoreq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, src, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = num;
			num ^= num2;
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = num;
			esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			eprintf ("esil_xoreq: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_syscall_linux_i386(RAnalEsil *esil) {
	ut32 sn, ret = 0;
	char *usn = r_anal_esil_pop (esil);
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
		eprintf ("Interrupt 0x%x not handled.", sn);
		esil->trap = R_ANAL_TRAP_UNHANDLED;
		esil->trap_code = sn;
		return -1;
	}
#undef r
#define r(x) r_reg_getv(esil->anal->reg, "##x##")
#undef rs
#define rs(x,y) r_reg_setv(esil->anal->reg, "##x##",y)
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

static int esil_syscall(RAnalEsil *esil) {
	// pop number
	// resolve arguments and run syscall handler
	eprintf ("SYSCALL: Not yet implemented\n");
	return esil_syscall_linux_i386 (esil);
}

static int esil_cmp(RAnalEsil *esil) {
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_get_parm (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
		}
	}
	free (dst);
	free (src);
	return ret;
}

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

JBE : CF = 1 || ZF = 1

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
static int esil_ifset(RAnalEsil *esil) {
	char *s, *src = r_anal_esil_pop (esil);
	for (s=src; *s; s++) {
		switch (*s) {
		case 'z':
			esil_reg_write (esil, "zf", R_BIT_CHK(&esil->flags, FLG(ZERO)));
			break;
		case 'c':
			esil_reg_write (esil, "cf", R_BIT_CHK(&esil->flags, FLG(CARRY)));
			break;
		case 'o':
			esil_reg_write (esil, "of", R_BIT_CHK(&esil->flags, FLG(OVERFLOW)));
			break;
		case 'p':
			esil_reg_write (esil, "pf", R_BIT_CHK(&esil->flags, FLG(PARITY)));
			break;
		}
	}
	free (src);
	return 0;
}

static int esil_if(RAnalEsil *esil) {
	ut64 onum, num = 0;
	char *src = r_anal_esil_pop (esil);
	if (src) {
		if (!isregornum (esil, src, &onum)) {
			int zf = R_BIT_CHK (&esil->flags, FLG(ZERO));
			int cf = R_BIT_CHK (&esil->flags, FLG(CARRY));
			if (!strcmp (src, "z")) {
				// equal, zero
				if (!zf) num = 1;
			} else
			if (!strcmp (src, "nz")) {
				// different, non-zero
				if (zf) num = 1;
			} else
			if (!strcmp (src, "a")) {
				// above
				if (!zf && !cf)
					num = 1;
			} else
			if (!strcmp (src, "ae")) {
				// above or equal
				if (!zf) num = 1;
				if (!zf && !cf) num = 1;
			} else
			if (!strcmp (src, "b")) {
				// below
				if (!zf && cf)
					num = 1;
			} else
			if (!strcmp (src, "be")) {
				// below or equal
				if (!zf) num = 1;
			} else num = onum;
		}
		if (!num) {
			// condition not matching, skipping until }
			esil->skip = R_TRUE;
		}
	}
	return 0;
}

static int esil_lsl(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			num <<= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			eprintf ("esil_neg: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_lsleq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			num <<= num2;
			esil->cur = num;
			esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			eprintf ("esil_neg: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_lsr(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_get_parm (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			num >>= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			eprintf ("esil_neg: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_lsreq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			num >>= num2;
			esil->cur = num;
			esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			eprintf ("esil_neg: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_and(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_get_parm (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			num &= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			eprintf ("esil_neg: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_xor(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			num ^= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			eprintf ("esil_xor: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_or(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_get_parm (esil, dst, &num)) {
		if (src && esil_get_parm (esil, src, &num2)) {
			num |= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			eprintf ("esil_xor: empty stack\n");
		}
	}
	free (src);
	free (dst);
	return ret;
}

R_API int r_anal_esil_dumpstack (RAnalEsil *esil) {
	int i;
	if (esil->trap) {
		eprintf ("ESIL TRAP type %d 0x%x\n",
			esil->trap, esil->trap_code);
	}
	if (esil->stackptr<1) 
		return 0;
	eprintf ("StackDump:\n");
	for (i=esil->stackptr-1;i>=0; i--) {
		eprintf (" [%d] %s\n", i, esil->stack[i]);
	}
	return 1;
}

static int esil_div(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_get_parm (esil, dst, &d)) {
			if (s == 0) {
				eprintf ("esil_div: Division by zero!\n");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else  {
				r_anal_esil_pushnum (esil, d/s);
			}
			ret = 1;
		}
	} else {
		eprintf ("esil_eq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_diveq (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (s == 0) {
				eprintf ("esil_diveq: Division by zero!\n");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else  {
				if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
					esil->old = d;
					esil->cur = d/s;
				}
				esil_reg_write (esil, dst, d/s);
			}
			ret = 1;
		} else {
			eprintf ("esil_diveq: empty stack\n");
		}
	} else {
		eprintf ("esil_diveq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_mul(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, d*s);
			ret = 1;
		} else {
			eprintf ("esil_mul: empty stack\n");
		}
	} else {
		eprintf ("esil_mul: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_muleq (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = d;
			esil_reg_write (esil, dst, s*d);
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = d*s;
			ret = 1;
		} else {
			eprintf ("esil_muleq: empty stack\n");
		}
	} else {
		eprintf ("esil_muleq: invalid parameters\n");
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_add (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, s+d);
			ret = 1;
		}
	} else {
		eprintf ("esil_add: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_addeq (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = d;
			esil_reg_write (esil, dst, d+s);
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = d+s;
		}
	} else {
		eprintf ("esil_addeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_sub (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, s-d);
		}
	} else {
		eprintf ("esil_sub: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_subeq (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = d;
			esil_reg_write (esil, dst, d-s);
			if (esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = d-s;
		}
	} else {
		eprintf ("esil_eq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_poke1(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, addr;
	ut8 num1;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && isregornum (esil, src, &num)) {
		if (dst && isregornum (esil, dst, &addr)) {
			num1 = (ut8)num;
			ret = esil_mem_write (esil, addr,
				(const ut8*)&num1, 1);
		}
	}
	return ret;
}

static int esil_poke4(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, addr;
	ut32 num4;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && isregornum (esil, src, &num)) {
		if (dst && isregornum (esil, dst, &addr)) {
			num4 = (ut32)num;
			ret = esil_mem_write (esil, addr,
				(const ut8*)&num4, 4);
		}
	}
	return ret;
}

static int esil_peek1(RAnalEsil *esil) {
	int ret = 0;
	char res[32];
	ut64 num;
	char *dst = r_anal_esil_pop (esil);
	if (dst && isregornum (esil, dst, &num)) {
		ut8 buf;
		ret = esil_mem_read (esil, num, &buf, 1);
		snprintf (res, sizeof (res), "0x%x", buf);
		r_anal_esil_push (esil, res);
	}
	free (dst);
	return ret;
}

static int esil_peek2(RAnalEsil *esil) {
	int ret = 0;
	char res[32];
	ut64 num;
	char *dst = r_anal_esil_pop (esil);
	if (dst && isregornum (esil, dst, &num)) {
		ut8 buf[4];
		ut16 *n16 = (ut16 *)&buf;
		ret = esil_mem_read (esil, num, buf, 2);
		snprintf (res, sizeof (res), "0x%hx", *n16);
		r_anal_esil_push (esil, res);
	}
	free (dst);
	return ret;
}

static int esil_peek4(RAnalEsil *esil) {
	int ret = 0;
	char res[32];
	ut64 num;
	char *dst = r_anal_esil_pop (esil);
	if (dst && isregornum (esil, dst, &num)) {
		ut8 buf[4];
		ut32 *n32 = (ut32 *)&buf;
		ret = esil_mem_read (esil, num, buf, 4);
		snprintf (res, sizeof (res), "0x%x", *n32);
		r_anal_esil_push (esil, res);
	}
	free (dst);
	return ret;
}

static int esil_poke8(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, addr;
	ut64 num8;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && isregornum (esil, src, &num)) {
		if (dst && isregornum (esil, dst, &addr)) {
			num8 = (ut64)num;
			ret = esil_mem_write (esil, addr,
				(const ut8*)&num8, sizeof (num8));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_peek8(RAnalEsil *esil) {
	int ret = 0;
	char res[32];
	ut64 num;
	char *dst = r_anal_esil_pop (esil);
	if (dst && isregornum (esil, dst, &num)) {
		ut8 buf[8];
		ut64 *n64 = (ut64 *)&buf;
		ret = esil_mem_read (esil, num, buf, sizeof (ut64));
		snprintf (res, sizeof (res), "0x%"PFMT64x, *n64);
		r_anal_esil_push (esil, res);
	}
	free (dst);
	return ret;
}

static int esil_peek(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_peek8 (esil);
	case 32: return esil_peek4 (esil);
	case 16: return esil_peek2 (esil);
	case 8: return esil_peek1 (esil);
	}
	return 0;
}

static int esil_smaller(RAnalEsil *esil) {		// 'src < dst' => 'src,dst,<'
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && isregornum (esil, src, &s)) {
		if (dst && isregornum (esil, dst, &d)) {
			r_anal_esil_pushnum(esil, (s < d));
			ret = 1;
		} else {
			eprintf ("esil_smaller: dst is broken\n");
		}
	} else {
		eprintf ("esil_smaller: src is broken\n");
	}
	free (src);
	free (dst);
	return ret;
}

// TODO: 
// sign is not handled
// ESIL flags not updated?
static int esil_bigger(RAnalEsil *esil) {		// 'src > dst' => 'src,dst,>'
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && isregornum (esil, src, &s)) {
		if (dst && isregornum (esil, dst, &d)) {
			r_anal_esil_pushnum(esil, (s > d));
			ret = 1;
		} else {
			eprintf ("esil_bigger: dst is broken\n");
		}
	} else {
		eprintf ("esil_bigger: src is broken\n");
	}
	free (src);
	free (dst);
	return ret;
}
static int esil_smaller_equal(RAnalEsil *esil) {		// 'src <= dst' => 'src,dst,<='
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && isregornum (esil, src, &s)) {
		if (dst && isregornum (esil, dst, &d)) {
			r_anal_esil_pushnum(esil, (s <= d));
			ret = 1;
		} else {
			eprintf ("esil_smaller_equal: dst is broken\n");
		}
	} else {
		eprintf ("esil_smaller_equal: src is broken\n");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_bigger_equal(RAnalEsil *esil) {		// 'src >= dst' => 'src,dst,>='
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && isregornum (esil, src, &s)) {
		if (dst && isregornum (esil, dst, &d)) {
			r_anal_esil_pushnum(esil, (s >= d));
			ret = 1;
		} else {
			eprintf ("esil_bigger_equal: dst is broken\n");
		}
	} else {
		eprintf ("esil_bigger_equal: src is broken\n");
	}
	free (src);
	free (dst);
	return ret;
}


static int iscommand (RAnalEsil *esil, const char *word, RAnalEsilOp *op) {
	char t[128];
	char *h;
	h = sdb_itoa(sdb_hash (word), t, 16);
	if (sdb_num_exists (esil->ops, h)) {
		*op = (RAnalEsilOp) sdb_num_get (esil->ops, h, 0);
		return R_TRUE;
	}
	return R_FALSE;
}

static int runword (RAnalEsil *esil, const char *word) {
	RAnalEsilOp op = NULL;
	if (esil->skip) {
		if (!strcmp (word, "}"))
			esil->skip = 0;
		return 0;
	} else {
		if (!strcmp (word, "}{")) {
			esil->skip = 1;
			return 0;
		}
	}
	if (iscommand (esil, word, &op)) {
		// run action
		if (op)
			return op (esil);
	}
	// push value
	r_anal_esil_push (esil, word);
	return 0;
}

R_API int r_anal_esil_parse(RAnalEsil *esil, const char *str) {
	int wordi = 0;
	char word[64];
	const char *ostr = str;
	esil->trap = 0;
	loop:
	esil->repeat = 0;
	wordi = 0;
	str = ostr;
	while (*str) {
		if (wordi>62) {
			eprintf ("Invalid esil string\n");
			return -1;
		}
		if (*str == ';') {
			word[wordi] = 0;
			wordi = 0;
			runword (esil, word);
			if (esil->repeat)
				goto loop;
			return 0;
		}
		if (*str == ',') {
			word[wordi] = 0;
			wordi = 0;
			runword (esil, word);
			if (esil->repeat)
				goto loop;
			str++;
		}
		word[wordi++] = *str;
		str++;
	}
	word[wordi] = 0;
	runword (esil, word);
	if (esil->repeat)
		goto loop;
	return 0;
}

R_API int r_anal_esil_setup (RAnalEsil *esil, RAnal *anal) {
	// register callbacks using this anal module.
	// this is: set
	esil->debug = 1;
	esil->anal = anal;
	esil->trap = 0;
	esil->trap_code = 0;
	//esil->user = NULL;
	esil->reg_read = internal_esil_reg_read;
	esil->reg_write = internal_esil_reg_write;
	esil->mem_read = internal_esil_mem_read;
	esil->mem_write = internal_esil_mem_write;
	r_anal_esil_set_op (esil, "$", esil_syscall);
	r_anal_esil_set_op (esil, "==", esil_cmp);
	r_anal_esil_set_op (esil, "<", esil_smaller);
	r_anal_esil_set_op (esil, ">", esil_bigger);
	r_anal_esil_set_op (esil, "<=", esil_smaller_equal);
	r_anal_esil_set_op (esil, ">=", esil_bigger_equal);
	r_anal_esil_set_op (esil, "?{", esil_if);
	r_anal_esil_set_op (esil, "<<", esil_lsl);
	r_anal_esil_set_op (esil, "<<=", esil_lsleq);
	r_anal_esil_set_op (esil, ">>", esil_lsr);
	r_anal_esil_set_op (esil, ">>=", esil_lsreq);
	r_anal_esil_set_op (esil, "&", esil_and);
	r_anal_esil_set_op (esil, "&=", esil_andeq);
	r_anal_esil_set_op (esil, "|", esil_or);
	r_anal_esil_set_op (esil, "|=", esil_oreq);
	r_anal_esil_set_op (esil, "!", esil_neg);
	r_anal_esil_set_op (esil, "!=", esil_negeq);
	r_anal_esil_set_op (esil, "=", esil_eq);
	r_anal_esil_set_op (esil, "*", esil_mul);
	r_anal_esil_set_op (esil, "*=", esil_muleq);
	r_anal_esil_set_op (esil, "^", esil_xor);
	r_anal_esil_set_op (esil, "^=", esil_xoreq);
	r_anal_esil_set_op (esil, "+", esil_add);
	r_anal_esil_set_op (esil, "+=", esil_addeq);
	r_anal_esil_set_op (esil, "-", esil_sub);
	r_anal_esil_set_op (esil, "-=", esil_subeq);
	r_anal_esil_set_op (esil, "/", esil_div);
	r_anal_esil_set_op (esil, "/=", esil_diveq);
	r_anal_esil_set_op (esil, "=[1]", esil_poke1);
	r_anal_esil_set_op (esil, "=[4]", esil_poke4);
	r_anal_esil_set_op (esil, "=[8]", esil_poke8);
	r_anal_esil_set_op (esil, "[1]", esil_peek1);
	r_anal_esil_set_op (esil, "[4]", esil_peek4);
	r_anal_esil_set_op (esil, "[8]", esil_peek8);
	r_anal_esil_set_op (esil, "[]", esil_peek);
	if (anal->cur && anal->cur->esil_init && anal->cur->esil_fini)
		return anal->cur->esil_init (esil);
	return R_TRUE;
}
