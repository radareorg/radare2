/* radare - LGPL - Copyright 2014 - pancake, condret */

#include <r_anal.h>
#include <r_types.h>
#include <r_util.h>
#include <r_db.h>

#define FLG(x) R_ANAL_ESIL_FLAG_##x
#define cpuflag(x,y) if (y) { R_BIT_SET (&esil->flags, FLG(x)); } else { R_BIT_UNSET (&esil->flags, FLG(x)); }
static int esil_reg_write (RAnalEsil *esil, const char *dst, ut64 num);
static int esil_reg_read (RAnalEsil *esil, const char *regname, ut64 *num);

/* Returns the number that has bits+1 least significant bits set. */
static inline ut64 mask (int bits) {
	return (ut64)(((st64)2) << bits) - 1;
}

/* magic limit */
#define R_ANAL_ESIL_GOTO_LIMIT 457
// TODO: this must be configurable from 'e' somehow

R_API RAnalEsil *r_anal_esil_new() {
	RAnalEsil *esil = R_NEW0 (RAnalEsil);
	if (!esil) return NULL;
	esil->parse_goto_limit = R_ANAL_ESIL_GOTO_LIMIT;
	esil->parse_goto_count = esil->parse_goto_limit;
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
	sdb_num_set (esil->ops, h, (ut64)(size_t)code, 0);
	if (!sdb_num_exists (esil->ops, h))
		eprintf ("can't set esil-op %s\n", op);
	return R_TRUE;
}

R_API int r_anal_esil_set_offset(RAnalEsil *esil, ut64 off) {
	if (esil) {
		esil->offset = off;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API void r_anal_esil_free (RAnalEsil *esil) {
	if (!esil)
		return;
	sdb_free (esil->ops);
	esil->ops = NULL;
	sdb_free (esil->stats);
	esil->stats = NULL;
	r_anal_esil_stack_free (esil);
	if (esil->anal && esil->anal->cur && esil->anal->cur->esil_fini)
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
	r_mem_copyendian (buf, buf, len ,!esil->anal->big_endian);
	if (esil->debug) {
		eprintf ("0x%08"PFMT64x" R> ", addr);
		for (i=0; i<len; i++)
			eprintf ("%02x", buf[i]);
		eprintf ("\n");
	}
	return ret;
}

static int internal_esil_mem_write (RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	if (!esil || !esil->anal || !esil->anal->iob.io)
		return 0;
	return esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len);
}

static int esil_mem_write (RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int i, ret = 0;
	if (!buf || !esil)
		return 0;
	r_mem_copyendian ((ut8*)buf, (ut8*)buf, len ,!esil->anal->big_endian);
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
	bit = ((bit & 0x3f) + 0x3f) & 0x3f;	//safer-sex version of -1
	return ((esil->old & mask(bit)) < (esil->cur & mask(bit)));
}

static int esil_internal_carry_check (RAnalEsil *esil, ut8 bit) {
	bit &= 0x3f;				//say no to weird bitshifts
	return ((esil->cur & mask(bit)) < (esil->old & mask(bit)));
}

static int esil_internal_parity_check (RAnalEsil *esil) {
	int i, bits = 0;
	ut64 mask = 1;
	for (i=0; i<64; i++) {
		if (esil->cur & mask)
			bits++;
		mask = (ut64)(mask>>1);						//yes, this cast is needed since every shift will produce a ut32
	}
	return (bits & 1);
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
	if (!esil || esil->stackptr<1)
		return NULL;
	return esil->stack[--esil->stackptr];
}

R_API int r_anal_esil_get_parm_type (RAnalEsil *esil, const char *str) {
	int len, i;
	if (!str || !(len=strlen(str)))
		return R_ANAL_ESIL_PARM_INVALID;
	if (str[0] == ESIL_INTERNAL_PREFIX) {
		if (len > 1)
			return R_ANAL_ESIL_PARM_INTERNAL;
		return R_ANAL_ESIL_PARM_INVALID;
	}
	if (!strncmp (str, "0x", 2))
		return R_ANAL_ESIL_PARM_NUM;
	if (!((str[0] >= '0' && str[0] <= '9')||str[0]=='-'))
		goto not_a_number;
	for (i = 1; i < len; i++)
		if (!(str[i] >= '0' && str[i] <= '9'))
			goto not_a_number;
	return R_ANAL_ESIL_PARM_NUM;
	not_a_number:
	if (r_reg_get (esil->anal->reg, str, -1))
		return R_ANAL_ESIL_PARM_REG;
	return R_ANAL_ESIL_PARM_INVALID;
}

static int esil_internal_read (RAnalEsil *esil, const char *str, ut64 *num) {
	ut8 bit;
	if (!str)
		return R_FALSE;
	if (esil->hook_flag_read) {
		int ret = esil->hook_flag_read (esil, str+1, num);
		if (ret)
			return R_TRUE;
	}
	switch (str[1]) {
	case '%':
		*num = esil->offset;
		break;
	case 'z':						//zero-flag
		*num = (esil->cur == 0);
		break;
	case 'b':						//borrow
		bit = (ut8) r_num_get (NULL, &str[2]);
		*num = esil_internal_borrow_check (esil, bit);
		break;
	case 'c':						//carry
		bit = (ut8) r_num_get (NULL, &str[2]);
		*num = esil_internal_carry_check (esil, bit);
		break;
		//case 'o':						//overflow
	case 'p':						//parity
		*num = esil_internal_parity_check (esil);
		break;
	case 'r':
		*num = esil->anal->bits/8;
		break;
	default:
		return R_FALSE;
	}
	return R_TRUE;
}

R_API int r_anal_esil_get_parm (RAnalEsil *esil, const char *str, ut64 *num) {
	int parm_type = r_anal_esil_get_parm_type (esil, str);
	if (!num || !esil) return R_FALSE;
	switch (parm_type) {
	case R_ANAL_ESIL_PARM_INTERNAL:
		//*num = esil_internal_read (esil, str, num);
		return esil_internal_read (esil, str, num);
	case R_ANAL_ESIL_PARM_NUM:
		*num = r_num_get (NULL, str);
		return R_TRUE;
	case R_ANAL_ESIL_PARM_REG:
		if (!esil_reg_read (esil, str, num))
			break;
		return R_TRUE;
	default:
		eprintf ("Invalid arg (%s)\n", str);
		esil->parse_stop = 1;
		break;
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
	ut64 num, n;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && dst && esil_reg_read (esil, dst, NULL)) {
		if (r_anal_esil_get_parm (esil, src, &num)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)		//necessary for some flag-things
				esil->cur = num;
			n = num;
			if (esil_reg_read (esil, dst, &num)) {
				if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
					esil->old = num;
				ret = esil_reg_write (esil, dst, n);
			} else eprintf ("esil_eq: invalid dest\n");
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
	if (src) {
		if (r_anal_esil_get_parm (esil, src, &num)) {
			r_anal_esil_pushnum (esil, !!!num);
			ret = 1;
		} else {
			if (isregornum (esil, src, &num)) {
				ret = 1;
				r_anal_esil_pushnum (esil, !!!num);
			} else eprintf ("esil_neg: trashed stack wtf? %s\n", src);
		}
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
	//r_anal_esil_pushnum (esil, ret);
	return ret;
}

static int esil_nop(RAnalEsil *esil) {
	return 0;
}

static int esil_andeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && esil_reg_read (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = num;
			num &= num2;
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
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
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = num;
			num |= num2;
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
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
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = num;
			num ^= num2;
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
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

static int esil_trap(RAnalEsil *esil) {
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && dst) {
		if (r_anal_esil_get_parm (esil, src, &s)) {
			if (r_anal_esil_get_parm (esil, dst, &d)) {
				esil->trap = s;
				esil->trap_code = d;
				return 1;
			} else eprintf ("esil_trap: missing parameter in stack\n");
		} else eprintf ("esil_trap: missing parameter in stack\n");
	}
	return 0;
}

static int esil_syscall(RAnalEsil *esil) {
	if (esil && esil->anal && esil->anal->cur && esil->anal->cur->esil_trap) {
		return esil->anal->cur->esil_trap (esil);
	}
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
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
		}
	}
	free (dst);
	free (src);

	//r_anal_esil_pushnum (esil, ret);
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
#if 0
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
#endif

static int esil_if(RAnalEsil *esil) {
	ut64 num;
	char *src = r_anal_esil_pop (esil);
	if (src) {
		// TODO: check return value
		(void)r_anal_esil_get_parm (esil, src, &num);
			// condition not matching, skipping until }
		if (!num)
			esil->skip = R_TRUE;
		return R_TRUE;
	}
	return R_FALSE;
}

static int esil_lsl(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num <<= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			eprintf ("esil_lsl: empty stack\n");
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
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			num <<= num2;
			esil->cur = num;
			esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			eprintf ("esil_lsleq: empty stack\n");
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
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
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
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			num >>= num2;
			esil->cur = num;
			esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			eprintf ("esil_lsreq: empty stack\n");
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
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num &= num2;
			r_anal_esil_pushnum (esil, num);
			ret = 1;
		} else {
			eprintf ("esil_and: empty stack\n");
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
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
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
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
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
	//eprintf ("StackDump:\n");
	for (i=esil->stackptr-1; i>=0; i--) {
		esil->anal->printf ("%s\n", esil->stack[i]);
	}
	return 1;
}

static int esil_break(RAnalEsil *esil) {
	esil->parse_stop = 1;
	return 1;
}

static int esil_clear(RAnalEsil *esil) {
	char *r;
	while ((r = r_anal_esil_pop (esil)))
		free (r);
	return 1;
}

static int esil_todo(RAnalEsil *esil) {
	esil->parse_stop = 2;
	return 1;
}

static int esil_goto(RAnalEsil *esil) {
	ut64 num = 0;
	char *src = r_anal_esil_pop (esil);
	if (src && *src && r_anal_esil_get_parm (esil, src, &num)) {
		esil->parse_goto = num;
	}
	free (src);
	return 1;
}

static int esil_pop(RAnalEsil *esil) {
	char *dst = r_anal_esil_pop (esil);
	free (dst);
	return 1;
}

static int esil_div(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
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
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (s == 0) {
				eprintf ("esil_diveq: Division by zero!\n");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else  {
				if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
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
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
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
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = d;
			esil_reg_write (esil, dst, s*d);
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = d*s;
			ret = R_TRUE;
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
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, s+d);
			ret = R_TRUE;
		}
	} else {
		eprintf ("esil_add: invalid parameters\n");
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
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = d;
			esil_reg_write (esil, dst, d+s);
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = d+s;
			ret = R_TRUE;
		}
	} else {
		eprintf ("esil_addeq: invalid parameters\n");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_inc (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s++;
		r_anal_esil_pushnum (esil, s);
		ret = R_TRUE;
	} else {
		eprintf ("esil_inc: invalid parameters\n");
	}
	free (src);
	return ret;
}

static int esil_inceq (RAnalEsil *esil) {
	int ret = 0;
	ut64 sd;
	char *src_dst = r_anal_esil_pop (esil);
	if (src_dst && (r_anal_esil_get_parm_type (esil, src_dst) == R_ANAL_ESIL_PARM_REG) && r_anal_esil_get_parm (esil, src_dst, &sd)) {
		esil->old = sd;
		sd++;
		esil->cur = sd;
		esil_reg_write (esil, src_dst, sd);
		ret = R_TRUE;
	} else {
		eprintf ("esil_inceq: invalid parameters\n");
	}
	free (src_dst);
	return ret;
}

static int esil_sub (RAnalEsil *esil) {
	int ret = 0;
	ut64 s = 0, d = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, s-d);
			ret = R_TRUE;
		} else {
			eprintf ("esil_sub: invalid parameters");
		}
	} else {
		eprintf ("esil_sub: invalid parameters\n");
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
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && esil_reg_read (esil, dst, &d)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->old = d;
			esil_reg_write (esil, dst, d-s);
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL)
				esil->cur = d-s;
			ret = R_TRUE;
		}
	} else {
		eprintf ("esil_subeq: invalid parameters\n");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_dec (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s--;
		r_anal_esil_pushnum (esil, s);
		ret = R_TRUE;
	} else {
		eprintf ("esil_dec: invalid parameters\n");
	}
	free (src);
	return ret;
}

static int esil_deceq (RAnalEsil *esil) {
	int ret = 0;
	ut64 sd;
	char *src_dst = r_anal_esil_pop (esil);
	if (src_dst && (r_anal_esil_get_parm_type (esil, src_dst) == R_ANAL_ESIL_PARM_REG) && r_anal_esil_get_parm (esil, src_dst, &sd)) {
		esil->old = sd;
		sd--;
		esil->cur = sd;
		esil_reg_write (esil, src_dst, sd);
		ret = R_TRUE;
	} else {
		eprintf ("esil_deceq: invalid parameters\n");
	}
	free (src_dst);
	return ret;
}

static int esil_poke1(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, addr;
	ut8 num1;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &addr)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil_mem_read (esil, addr, &num1, 1);
				esil->old = num1;
				esil->cur = (num & 0xff);
			}
			num1 = (ut8)num;
			ret = esil_mem_write (esil, addr,
				(const ut8*)&num1, 1);
		}
	}
	return ret;
}

static int esil_poke2(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, addr;
	ut16 num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &addr)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil_mem_read (esil, addr, (ut8 *)&num2, 2);
				esil->old = num2;
				esil->cur = (num & 0xffff);
			}
			num2 = (ut16)num;
			ret = esil_mem_write (esil, addr,
				(const ut8*)&num2, 2);
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
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &addr)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil_mem_read (esil, addr, (ut8 *)&num4, 4);
				esil->old = num4;
				esil->cur = (num & 0xffffffff);
			}
			num4 = (ut32)num;
			ret = esil_mem_write (esil, addr,
				(const ut8*)&num4, 4);
		}
	}
	return ret;
}

static int esil_poke8(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, addr, num8;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &addr)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil_mem_read (esil, addr, (ut8 *)&num8, 8);
				esil->old = num8;
				esil->cur = num;
			}
			num8 = (ut64)num;
			ret = esil_mem_write (esil, addr,
				(const ut8*)&num8, sizeof (num8));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_poke(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_poke8 (esil);
	case 32: return esil_poke4 (esil);
	case 16: return esil_poke2 (esil);
	case 8: return esil_poke1 (esil);
	}
	return 0;
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

static int esil_mem_oreq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);				//save the dst-addr
	char *src0 = r_anal_esil_pop (esil);				//get the src
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {		//get the src
		ret = 1;
		r_anal_esil_push (esil, dst);				//push the dst-addr
		ret &= esil_peek1 (esil);				//read
		src1 = r_anal_esil_pop (esil);				//get the old dst-value
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {	//get the old dst-value
			d |= s;						//calculate the new dst-value
			r_anal_esil_pushnum (esil, d);			//push the new dst-value
			r_anal_esil_push (esil, dst);			//push the dst-addr
			ret &= esil_poke1 (esil);			//write
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_oreq1: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_oreq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek2 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d |= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_oreq2: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_oreq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek4 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d |= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_oreq4: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_oreq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek8 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d |= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke8 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_oreq8: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_oreq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_oreq8 (esil);
	case 32: return esil_mem_oreq4 (esil);
	case 16: return esil_mem_oreq2 (esil);
	case 8: return esil_mem_oreq1 (esil);
	}
	return 0;
}

static int esil_mem_xoreq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek1 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d ^= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke1 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_xoreq1: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_xoreq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek2 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d ^= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_xoreq2: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_xoreq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek4 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d ^= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_xoreq4: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_xoreq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek8 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d ^= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke8 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_xoreq8: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_xoreq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_xoreq8 (esil);
	case 32: return esil_mem_xoreq4 (esil);
	case 16: return esil_mem_xoreq2 (esil);
	case 8: return esil_mem_xoreq1 (esil);
	}
	return 0;
}

static int esil_mem_andeq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek1 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d &= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke1 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_andeq1: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_andeq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek2 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d &= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_andeq2: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_andeq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek4 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d &= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_andeq4: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_andeq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek8 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d &= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke8 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_andeq8: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_andeq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_andeq8 (esil);
	case 32: return esil_mem_andeq4 (esil);
	case 16: return esil_mem_andeq2 (esil);
	case 8: return esil_mem_andeq1 (esil);
	}
	return 0;
}

static int esil_mem_addeq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek1 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d += s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke1 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_addeq1: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_addeq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek2 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d += s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_addeq2: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_addeq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek4 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d += s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_addeq4: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_addeq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek8 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d += s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke8 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_addeq8: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_addeq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_addeq8 (esil);
	case 32: return esil_mem_addeq4 (esil);
	case 16: return esil_mem_addeq2 (esil);
	case 8: return esil_mem_addeq1 (esil);
	}
	return 0;
}

static int esil_mem_subeq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek1 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d -= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke1 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_subeq1: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_subeq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek2 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d -= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_subeq2: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_subeq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek4 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d -= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_subeq4: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_subeq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek8 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d -= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke8 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_subeq8: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_subeq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_subeq8 (esil);
	case 32: return esil_mem_subeq4 (esil);
	case 16: return esil_mem_subeq2 (esil);
	case 8: return esil_mem_subeq1 (esil);
	}
	return 0;
}

static int esil_mem_muleq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek1 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d *= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke1 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_muleq1: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_muleq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek2 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d *= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_muleq2: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_muleq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek4 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d *= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_muleq4: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_muleq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		ret = 1;
		r_anal_esil_push (esil, dst);
		ret &= esil_peek8 (esil);
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d *= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= esil_poke8 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_muleq8: invalid parameters\n");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_muleq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_muleq8 (esil);
	case 32: return esil_mem_muleq4 (esil);
	case 16: return esil_mem_muleq2 (esil);
	case 8: return esil_mem_muleq1 (esil);
	}
	return 0;
}

static int esil_mem_inceq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek1 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s++;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke1 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_inceq1: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_inceq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek2 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s++;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_inceq2: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_inceq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek4 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s++;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_inceq4: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_inceq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek8 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s++;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke8 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_inceq8: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_inceq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_inceq8 (esil);
	case 32: return esil_mem_inceq4 (esil);
	case 16: return esil_mem_inceq2 (esil);
	case 8: return esil_mem_inceq1 (esil);
	}
	return 0;
}

static int esil_mem_deceq1 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek1 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s--;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke1 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_deceq1: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_deceq2 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek2 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s--;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke2 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_deceq2: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_deceq4 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek4 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s--;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke4 (esil);
		} else	ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_deceq4: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_deceq8 (RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		ret = 1;
		r_anal_esil_push (esil, off);
		ret &= esil_peek8 (esil);
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s--;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= esil_poke8 (esil);
		} else ret = 0;
	}
	if (!ret)
		eprintf ("esil_mem_deceq8: invalid parameters\n");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_deceq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_deceq8 (esil);
	case 32: return esil_mem_deceq4 (esil);
	case 16: return esil_mem_deceq2 (esil);
	case 8: return esil_mem_deceq1 (esil);
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
	h = sdb_itoa (sdb_hash (word), t, 16);
	if (sdb_num_exists (esil->ops, h)) {
		*op = (RAnalEsilOp) (size_t)sdb_num_get (esil->ops, h, 0);
		return R_TRUE;
	}
	return R_FALSE;
}

static int runword (RAnalEsil *esil, const char *word) {
	RAnalEsilOp op = NULL;
	esil->parse_goto_count--;

	if (esil->parse_goto_count<1) {
		eprintf ("ESIL infinite loop detected\n");
		esil->trap = 1; // INTERNAL ERROR
		esil->parse_stop = 1; // INTERNAL ERROR
		return 0;
	}

//eprintf ("WORD (%d) (%s)\n", esil->skip, word);
	if (!strcmp (word, "}{")) {
		esil->skip = esil->skip? 0: 1;
		return 1;
	} else if (!strcmp (word, "}")) {
		esil->skip = 0;
		return 1;
	}
	if (esil->skip) {
		return 1;
	}

	if (iscommand (esil, word, &op)) {
		// run action
		if (op) {
			if (esil->hook_command) {
				if (esil->hook_command (esil, word))
					return 1; // XXX cannot return != 1
			}
			return op (esil);
		}
	}
	if (!*word || *word==',') {
		// skip empty words
		return 1;
	}
	// push value
	if (!r_anal_esil_push (esil, word)) {
		eprintf ("ESIL stack is full\n");
		esil->trap = 1;
		esil->trap_code = 1;
	}
	return 1;
}

static const char *gotoWord(const char *str, int n) {
	const char *ostr = str;
	int count = 0;
	while (*str) {
		if (count == n)
			return ostr;
		str++;
		if (*str == ',') {
			ostr = str+1;
			count++;
		}
	}
	return NULL;
}

/** evaluate an esil word and return the action to perform
 * 0: continue running the
 * 1: stop execution
 * 2: continue in loop
 * 3: normal continuation
 */
static int evalWord (RAnalEsil *esil, const char *ostr, const char **str) {
	if ((*str)[0] && (*str)[1]==',')
		return 2;
	if (esil->repeat)
		return 0;
	if (esil->parse_goto != -1) {
		// TODO: detect infinite loop??? how??
		*str = gotoWord (ostr, esil->parse_goto);
		if (*str) {
			esil->parse_goto = -1;
			return 2;
		}
		eprintf ("Cannot find word %d\n", esil->parse_goto);
		return 1;
	}
	if (esil->parse_stop) {
		if (esil->parse_stop == 2) {
			eprintf ("ESIL TODO: %s\n", *str+1);
		}
		return 1;
	}
	return 3;
}

R_API int r_anal_esil_parse(RAnalEsil *esil, const char *str) {
	int wordi = 0;
	int dorunword;
	char word[64];
	const char *ostr = str;
	if (!esil)
		return 0;
	esil->trap = 0;
loop:
	esil->repeat = 0;
	esil->skip = 0;
	esil->parse_goto = -1;
	esil->parse_stop = 0;
	esil->parse_goto_count = esil->parse_goto_limit;
	str = ostr;
repeat:
	wordi = 0;
	while (*str) {
		if (wordi>62) {
			eprintf ("Invalid esil string\n");
			return -1;
		}
		dorunword = 0;
		if (*str == ';') {
			word[wordi] = 0;
			dorunword = 1;
		}
		if (*str == ',') {
			word[wordi] = 0;
			dorunword = 2;
		}

		if (dorunword) {
			if (!runword (esil, word)) {
				return 0;
			}
			word[wordi] = ',';
			wordi = 0;
			switch (evalWord (esil, ostr, &str)) {
			case 0: goto loop;
			case 1: return 0;
			case 2: continue;
			}
			if (dorunword==1)
				return 0;
			str++;
		}
		word[wordi++] = *str;
		str++;
	}
	word[wordi] = 0;
	if (*word) {
		if (!runword (esil, word))
			return 0;
		switch (evalWord (esil, ostr, &str)) {
		case 0: goto loop;
		case 1: return 0;
		case 2: goto repeat;
		}
	}
	return 1;
}

R_API void  r_anal_esil_stack_free (RAnalEsil *esil) {
	int i;
	if (esil) {
		for (i=0; i<esil->stackptr; i++)
			R_FREE (esil->stack[i]);
		esil->stackptr = 0;
	}
}

R_API int r_anal_esil_condition(RAnalEsil *esil, const char *str) {
	char *popped;
	int ret;
	if (!esil)
		return R_FALSE;
	while (*str==' ') str++; // use proper string chop?
	ret = r_anal_esil_parse (esil, str);
	popped = r_anal_esil_pop (esil);
	if (popped) {
		ut64 num;
		if (isregornum (esil, popped, &num)) {
			ret = !! num;
		} else ret = 0;
		free (popped);
	} else {
		eprintf ("ESIL stack is empty\n");
		return -1;
	}
	return ret;
}

R_API int r_anal_esil_setup (RAnalEsil *esil, RAnal *anal, int romem, int stats) {
	if (!esil)
		return R_FALSE;
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

	r_anal_esil_mem_ro (esil, romem);
	r_anal_esil_stats (esil, stats);

	r_anal_esil_set_op (esil, "$", esil_syscall);
	r_anal_esil_set_op (esil, "$$", esil_trap);
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
	r_anal_esil_set_op (esil, "}", esil_nop); // just to avoid push
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
	r_anal_esil_set_op (esil, "++", esil_inc);
	r_anal_esil_set_op (esil, "++=", esil_inceq);
	r_anal_esil_set_op (esil, "-", esil_sub);
	r_anal_esil_set_op (esil, "-=", esil_subeq);
	r_anal_esil_set_op (esil, "--", esil_dec);
	r_anal_esil_set_op (esil, "--=", esil_deceq);
	r_anal_esil_set_op (esil, "/", esil_div);
	r_anal_esil_set_op (esil, "/=", esil_diveq);
	r_anal_esil_set_op (esil, "=[]", esil_poke);
	r_anal_esil_set_op (esil, "=[1]", esil_poke1);
	r_anal_esil_set_op (esil, "=[2]", esil_poke2);
	r_anal_esil_set_op (esil, "=[4]", esil_poke4);
	r_anal_esil_set_op (esil, "=[8]", esil_poke8);
	r_anal_esil_set_op (esil, "|=[]", esil_mem_oreq);
	r_anal_esil_set_op (esil, "|=[1]", esil_mem_oreq1);
	r_anal_esil_set_op (esil, "|=[2]", esil_mem_oreq2);
	r_anal_esil_set_op (esil, "|=[4]", esil_mem_oreq4);
	r_anal_esil_set_op (esil, "|=[8]", esil_mem_oreq8);
	r_anal_esil_set_op (esil, "^=[]", esil_mem_xoreq);
	r_anal_esil_set_op (esil, "^=[1]", esil_mem_xoreq1);
	r_anal_esil_set_op (esil, "^=[2]", esil_mem_xoreq2);
	r_anal_esil_set_op (esil, "^=[4]", esil_mem_xoreq4);
	r_anal_esil_set_op (esil, "^=[8]", esil_mem_xoreq8);
	r_anal_esil_set_op (esil, "&=[]", esil_mem_andeq);
	r_anal_esil_set_op (esil, "&=[1]", esil_mem_andeq1);
	r_anal_esil_set_op (esil, "&=[2]", esil_mem_andeq2);
	r_anal_esil_set_op (esil, "&=[4]", esil_mem_andeq4);
	r_anal_esil_set_op (esil, "&=[8]", esil_mem_andeq8);
	r_anal_esil_set_op (esil, "+=[]", esil_mem_addeq);
	r_anal_esil_set_op (esil, "+=[1]", esil_mem_addeq1);
	r_anal_esil_set_op (esil, "+=[2]", esil_mem_addeq2);
	r_anal_esil_set_op (esil, "+=[4]", esil_mem_addeq4);
	r_anal_esil_set_op (esil, "+=[8]", esil_mem_addeq8);
	r_anal_esil_set_op (esil, "-=[]", esil_mem_subeq);
	r_anal_esil_set_op (esil, "-=[1]", esil_mem_subeq1);
	r_anal_esil_set_op (esil, "-=[2]", esil_mem_subeq2);
	r_anal_esil_set_op (esil, "-=[4]", esil_mem_subeq4);
	r_anal_esil_set_op (esil, "-=[8]", esil_mem_subeq8);
	r_anal_esil_set_op (esil, "*=[]", esil_mem_muleq);
	r_anal_esil_set_op (esil, "*=[1]", esil_mem_muleq1);
	r_anal_esil_set_op (esil, "*=[2]", esil_mem_muleq2);
	r_anal_esil_set_op (esil, "*=[4]", esil_mem_muleq4);
	r_anal_esil_set_op (esil, "*=[8]", esil_mem_muleq8);			//Warning esil_mem_diveq is not completely copy-pasta
	r_anal_esil_set_op (esil, "++=[]", esil_mem_inceq);
	r_anal_esil_set_op (esil, "++=[1]", esil_mem_inceq1);
	r_anal_esil_set_op (esil, "++=[2]", esil_mem_inceq2);
	r_anal_esil_set_op (esil, "++=[4]", esil_mem_inceq4);
	r_anal_esil_set_op (esil, "++=[8]", esil_mem_inceq8);
	r_anal_esil_set_op (esil, "--=[]", esil_mem_deceq);
	r_anal_esil_set_op (esil, "--=[1]", esil_mem_deceq1);
	r_anal_esil_set_op (esil, "--=[2]", esil_mem_deceq2);
	r_anal_esil_set_op (esil, "--=[4]", esil_mem_deceq4);
	r_anal_esil_set_op (esil, "--=[8]", esil_mem_deceq8);
	r_anal_esil_set_op (esil, "[]", esil_peek);
	r_anal_esil_set_op (esil, "[1]", esil_peek1);
	r_anal_esil_set_op (esil, "[2]", esil_peek2);
	r_anal_esil_set_op (esil, "[4]", esil_peek4);
	r_anal_esil_set_op (esil, "[8]", esil_peek8);
	r_anal_esil_set_op (esil, "STACK", r_anal_esil_dumpstack);
	r_anal_esil_set_op (esil, "POP", esil_pop);
	r_anal_esil_set_op (esil, "TODO", esil_todo);
	r_anal_esil_set_op (esil, "GOTO", esil_goto);
	r_anal_esil_set_op (esil, "BREAK", esil_break);
	r_anal_esil_set_op (esil, "CLEAR", esil_clear);
	if (anal->cur && anal->cur->esil_init && anal->cur->esil_fini)
		return anal->cur->esil_init (esil);
	return R_TRUE;
}
