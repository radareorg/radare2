/* radare - LGPL - Copyright 2014-2017 - pancake, condret */

#include <r_anal.h>
#include <r_types.h>
#include <r_util.h>
#include <r_bind.h>

#define IFDBG if (esil && esil->verbose > 1)
#define IFVBS if (esil && esil->verbose > 0)
#define FLG(x) R_ANAL_ESIL_FLAG_##x
#define cpuflag(x, y)\
if (esil) {\
	if (y) { \
		R_BIT_SET (&esil->flags, FLG (x));\
	} else { \
		R_BIT_UNSET (&esil->flags, FLG (x));\
	} \
}

/* internal helper functions */
static void err(RAnalEsil *esil, const char *msg) {
	if (esil->verbose) {
		eprintf ("0x%08" PFMT64x " %s\n", esil->address, msg);
	}
}
#define ERR(x) err(esil,x)

/* Returns the number that has bits + 1 least significant bits set. */
static inline ut64 genmask(int bits) {
	ut64 m = (ut64)(((ut64)(2) << bits) - 1);
	if (!m) m = UT64_MAX;
	return m;
}

static bool isnum(RAnalEsil *esil, const char *str, ut64 *num) {
	if (!esil || !str) {
		return false;
	}
	if (IS_DIGIT (*str)) {
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

static bool isregornum(RAnalEsil *esil, const char *str, ut64 *num) {
	if (!r_anal_esil_reg_read (esil, str, num, NULL)) {
		if (!isnum (esil, str, num)) {
			return false;
		}
	}
	return true;
}

/* pop Register or Number */
static bool popRN(RAnalEsil *esil, ut64 *n) {
	char *str = r_anal_esil_pop (esil);
	if (str) {
		bool ret = isregornum (esil, str, n);
		free (str);
		return ret;
	}
	return false;
}

/* R_ANAL_ESIL API */

R_API RAnalEsil *r_anal_esil_new(int stacksize, int iotrap) {
	RAnalEsil *esil = R_NEW0 (RAnalEsil);
	if (!esil) {
		return NULL;
	}
	if (stacksize < 3) {
		free (esil);
		return NULL;
	}
	if (!(esil->stack = calloc (sizeof (char *), stacksize))) {
		free (esil);
		return NULL;
	}
	esil->verbose = false;
	esil->stacksize = stacksize;
	esil->parse_goto_count = R_ANAL_ESIL_GOTO_LIMIT;
	esil->ops = sdb_new0 ();
	esil->iotrap = iotrap;
	esil->interrupts = sdb_new0 ();
	return esil;
}

R_API int r_anal_esil_set_op(RAnalEsil *esil, const char *op, RAnalEsilOp code) {
	char t[128];
	char *h;
	if (!code || !op || !strlen (op) || !esil || !esil->ops) {
		return false;
	}
	h = sdb_itoa (sdb_hash (op), t, 16);
	sdb_num_set (esil->ops, h, (ut64)(size_t)code, 0);
	if (!sdb_num_exists (esil->ops, h)) {
		eprintf ("can't set esil-op %s\n", op);
		return false;
	}
	return true;
}

R_API int r_anal_esil_set_interrupt(RAnalEsil *esil, int interrupt, RAnalEsilInterruptCB interruptcb) {
	char t[128];
	char *i;
	if (!esil || !esil->interrupts) {
		return false;
	}
	i = sdb_itoa ((ut64)interrupt, t, 16);
	sdb_num_set (esil->interrupts, i, (ut64)(size_t)interruptcb, 0);
	if (!sdb_num_exists (esil->interrupts, i)) {
		eprintf ("can't set interrupt-handler for interrupt %d\n", interrupt);
		return false;
	}
	return true;
}

R_API int r_anal_esil_fire_trap(RAnalEsil *esil, int trap_type, int trap_code) {
	if (!esil) {
		return false;
	}
	if (esil->cmd) {
		if (esil->cmd (esil, esil->cmd_trap, trap_type, trap_code)) {
			return true;
		}
	}
	if (esil->anal) {
		RAnalPlugin *ap = esil->anal->cur;
		if (ap && ap->esil_trap) {
			if (ap->esil_trap (esil, trap_type, trap_code)) {
				return true;
			}
		}
	}
#if 0
	RAnalEsilTrapCB icb;
	icb = (RAnalEsilTrapCB)sdb_ptr_get (esil->traps, i, 0);
	return icb (esil, trap_type, trap_code);
#endif
	return false;
}

R_API int r_anal_esil_fire_interrupt(RAnalEsil *esil, int interrupt) {
	char t[128];
	char *i;
	RAnalEsilInterruptCB icb;
	if (!esil) {
		return false;
	}
	if (esil->cmd && esil->cmd (esil, esil->cmd_intr, interrupt, 0)) {
		return true;
	}
	if (esil->anal) {
		RAnalPlugin *ap = esil->anal->cur;
		if (ap && ap->esil_intr) {
			if (ap->esil_intr (esil, interrupt))
				return true;
		}
	}
	if (!esil->interrupts)
		return false;
	i = sdb_itoa ((ut64)interrupt, t, 16);
	if (!sdb_num_exists (esil->interrupts, i)) {
		//eprintf ("0x%08"PFMT64x" Invalid interrupt/syscall 0x%08x\n", esil->address, interrupt);
		return false;
	}
	icb = (RAnalEsilInterruptCB)sdb_ptr_get (esil->interrupts, i, 0);
	if (icb) return icb (esil, interrupt);
	return false;
}

R_API bool r_anal_esil_set_pc(RAnalEsil *esil, ut64 addr) {
	if (esil) {
		esil->address = addr;
		return true;
	}
	return false;
}

R_API void r_anal_esil_free(RAnalEsil *esil) {
	if (!esil) {
		return;
	}
	if (esil->anal && esil == esil->anal->esil) {
		esil->anal->esil = NULL;
	}
	sdb_free (esil->ops);
	esil->ops = NULL;
	sdb_free (esil->interrupts);
	esil->interrupts = NULL;
	sdb_free (esil->stats);
	esil->stats = NULL;
	r_anal_esil_stack_free (esil);
	free (esil->stack);
	if (esil->anal && esil->anal->cur && esil->anal->cur->esil_fini) {
		esil->anal->cur->esil_fini (esil);
	}
	free (esil->cmd_intr);
	free (esil->cmd_trap);
	free (esil->cmd_mdev);
	free (esil->cmd_todo);
	free (esil->cmd_ioer);
	free (esil);
}

static ut8 esil_internal_sizeof_reg(RAnalEsil *esil, const char *r) {
	RRegItem *ri;
	if (!esil || !esil->anal || !esil->anal->reg || !r) {
		return 0;
	}
	ri = r_reg_get (esil->anal->reg, r, -1);
	return ri? ri->size: 0;
}

static int internal_esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	if (!esil || !esil->anal || !esil->anal->iob.io) {
		return 0;
	}
	if (esil->cmd_mdev && esil->mdev_range) {
		if (r_str_range_in (esil->mdev_range, addr)) {
			if (esil->cmd (esil, esil->cmd_mdev, addr, 0)) {
				return true;
			}
		}
	}
	return esil->anal->iob.read_at (esil->anal->iob.io, addr, buf, len);
}

static int internal_esil_mem_read_no_null(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	if (!esil || !esil->anal || !esil->anal->iob.io || !addr) {
		return 0;
	}
	return esil->anal->iob.read_at (esil->anal->iob.io, addr, buf, len);
}

R_API int r_anal_esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	int i, ret = 0;
	if (!buf || !esil) {
		return 0;
	}
	if (esil->cb.hook_mem_read) {
		ret = esil->cb.hook_mem_read (esil, addr, buf, len);
	}
	if (!ret && esil->cb.mem_read) {
		ret = esil->cb.mem_read (esil, addr, buf, len);
		if (ret != len) {
			if (esil->iotrap) {
				esil->trap = R_ANAL_TRAP_READ_ERR;
				esil->trap_code = addr;
			}
		}
	}
	IFDBG {
		eprintf ("0x%08" PFMT64x " R> ", addr);
		for (i = 0; i < len; i++) {
			eprintf ("%02x", buf[i]);
		}
		eprintf ("\n");
	}
	return ret;
}

static int internal_esil_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret;
	if (!esil || !esil->anal || !esil->anal->iob.io || esil->nowrite) {
		return 0;
	}
	if (esil->cmd_mdev && esil->mdev_range) {
		if (r_str_range_in (esil->mdev_range, addr)) {
			if (esil->cmd (esil, esil->cmd_mdev, addr, 1)) {
				return true;
			}
		}
	}
	ret = esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len);
	if (ret != len) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd (esil, esil->cmd_ioer, esil->address, 0);
		}
	}
	return ret;
}

static int internal_esil_mem_write_no_null(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret;
	if (!esil || !esil->anal || !esil->anal->iob.io || !addr) {
		return 0;
	}
	if (esil->nowrite) {
		return 0;
	}
	ret = esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len);
	if (ret != len) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
	}
	return ret;
}

R_API int r_anal_esil_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int i, ret = 0;
	if (!buf || !esil) {
		return 0;
	}
	IFDBG {
		eprintf ("0x%08" PFMT64x " <W ", addr);
		for (i = 0; i < len; i++) {
			eprintf ("%02x", buf[i]);
		}
		eprintf ("\n");
	}
	if (esil->cb.hook_mem_write) {
		ret = esil->cb.hook_mem_write (esil, addr, buf, len);
	}
	if (!ret && esil->cb.mem_write) {
		ret = esil->cb.mem_write (esil, addr, buf, len);
	}
	return ret;
}

static int internal_esil_reg_read(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (size) *size = reg->size;
		if (num) *num = r_reg_get_value (esil->anal->reg, reg);
		return true;
	}
	return false;
}

static int internal_esil_reg_write(RAnalEsil *esil, const char *regname, ut64 num) {
	if (esil && esil->anal) {
		RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
		if (reg) {
			r_reg_set_value (esil->anal->reg, reg, num);
			return true;
		}
	}
	return false;
}
static int internal_esil_reg_write_no_null (RAnalEsil *esil, const char *regname, ut64 num) {
	if (!esil || !esil->anal->reg) {
		return false;
	}
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	const char *pc = r_reg_get_name (esil->anal->reg, R_REG_NAME_PC);
	const char *sp = r_reg_get_name (esil->anal->reg, R_REG_NAME_SP);
	const char *bp = r_reg_get_name (esil->anal->reg, R_REG_NAME_BP);
	//trick to protect strcmp from segfaulting with out making the condition complex
	if (!pc) {
		pc = "pc";
	}
	if (!sp) {
		sp = "sp";
	}
	if (!bp) {
		bp = "bp";
	}
	if (reg && reg->name && ((strcmp (reg->name , pc) && strcmp (reg->name, sp) && strcmp(reg->name, bp)) || num)) { //I trust k-maps
		r_reg_set_value (esil->anal->reg, reg, num);
		return true;
	}
	return false;
}

static int esil_internal_borrow_check(RAnalEsil *esil, ut8 bit) {
	bit = ((bit & 0x3f) + 0x3f) & 0x3f;
	return ((esil->old & genmask (bit)) < (esil->cur & genmask (bit)));
}

static int esil_internal_carry_check(RAnalEsil *esil, ut8 bit) {
	ut64 mask = genmask (bit);
	return (esil->cur & mask) < (esil->old & mask);
}

static int esil_internal_parity_check(RAnalEsil *esil) {
	// Set if the number of set bits in the least significant _byte_ is a multiple of 2.
	//   - Taken from: https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits
	ut64 c1 = 0x0101010101010101ULL;
	ut64 c2 = 0x8040201008040201ULL;
	ut64 c3 = 0x1FF;
	// Take only the least significant byte.
	ut64 lsb = esil->cur & 0xff;
	return !((((lsb * c1) & c2) % c3) & 1);
}

static bool esil_internal_sign_check(RAnalEsil *esil) {
	if (!esil || !esil->lastsz) {
		return false;
	}
	return ((esil->cur >> (esil->lastsz - 1)) & 1);
}

static bool esil_internal_overflow_check(RAnalEsil *esil) {
	if (!esil || (esil->lastsz < 2)) {
		return false;
	}
	// According to wikipedia this should work
	return (esil_internal_carry_check (esil, esil->lastsz - 1) ^ esil_internal_carry_check (esil, esil->lastsz - 2));
}

R_API int r_anal_esil_pushnum(RAnalEsil *esil, ut64 num) {
	char str[64];
	snprintf (str, sizeof (str) - 1, "0x%" PFMT64x, num);
	return r_anal_esil_push (esil, str);
}

R_API bool r_anal_esil_push(RAnalEsil *esil, const char *str) {
	if (!str || !esil || !*str || esil->stackptr > (esil->stacksize - 1)) {
		return false;
	}
	esil->stack[esil->stackptr++] = strdup (str);
	return true;
}

R_API char *r_anal_esil_pop(RAnalEsil *esil) {
	if (!esil || esil->stackptr < 1) {
		return NULL;
	}
	return esil->stack[--esil->stackptr];
}

R_API int r_anal_esil_get_parm_type(RAnalEsil *esil, const char *str) {
	int len, i;

	if (!str || !(len = strlen (str))) {
		return R_ANAL_ESIL_PARM_INVALID;
	}
	if (str[0] == ESIL_INTERNAL_PREFIX && str[1]) {
		return R_ANAL_ESIL_PARM_INTERNAL;
	}
	if (!strncmp (str, "0x", 2))
		return R_ANAL_ESIL_PARM_NUM;
	if (!((IS_DIGIT(str[0])) || str[0] == '-'))
		goto not_a_number;
	for (i = 1; i < len; i++)
		if (!(IS_DIGIT(str[i])))
			goto not_a_number;
	return R_ANAL_ESIL_PARM_NUM;
not_a_number:
	if (r_reg_get (esil->anal->reg, str, -1))
		return R_ANAL_ESIL_PARM_REG;
	return R_ANAL_ESIL_PARM_INVALID;
}

static int esil_internal_read(RAnalEsil *esil, const char *str, ut64 *num) {
	ut8 bit;
	if (!esil || !str || !*str) {
		return false;
	}
	if (esil->cb.hook_flag_read) {
		if (esil->cb.hook_flag_read (esil, str + 1, num)) {
			return true;
		}
	}
	switch (str[1]) {
	case '$':
		*num = esil->address;
		break;
	case 'z': //zero-flag
		{
			ut64 m = genmask (esil->lastsz - 1);
			*num = (((ut64) esil->cur & m) == 0);
		}
		break;
	case 'b': //borrow
		bit = (ut8) r_num_get (NULL, &str[2]);
		*num = esil_internal_borrow_check (esil, bit);
		break;
	case 'c': //carry
		bit = (ut8) r_num_get (NULL, &str[2]);
		*num = esil_internal_carry_check (esil, bit);
		break;
	case 'o': //overflow
		*num = esil_internal_overflow_check (esil);
		break;
	case 'p': //parity
		*num = esil_internal_parity_check (esil);
		break;
	case 'r': //regsize in 8-bit-bytes
		*num = esil->anal->bits / 8;
		break;
	case 's': //sign
		*num = esil_internal_sign_check (esil);
		break;
	case 'd': //delay slot state
		switch (str[2]) {
		case 's':
			*num = esil->delay;
			break;
		default:
			return false;
		}
		break;
	case 'j': // jump target
		switch (str[2]) {
		case 't': // "$jt"
			*num = esil->jump_target;
			break;
		case 's': // "$js"
			*num = esil->jump_target_set;
			break;
		default:
			return false;
		}
		break;
	default:
		{
			// Handle the case of "internal set", i.e. set a register without
			// having side effects. The value to be set must be in decimal and
			// prefixed by "$". Example:
			//  - Set of to 0. ("$0,of,=")
			//  - Set rax to 100 without side-effects. ("$100,rax,=")
			char *endptr = NULL;
			ut64 imm = strtoull (str + 1, &endptr, 10);
			if (endptr == str + 1) {
				return false;
			}
			*num = imm;
		}
	}
	return true;
}

static int esil_internal_write(RAnalEsil *esil, const char *str, ut64 num) {
	if (!str || !*str || !esil) {
		return false;
	}
	switch (str[1]) {
	case 'd': //delay slot state
		switch (str[2]) {
		case 's':
			esil->delay = num;
			break;
		default:
			return false;
		}
		break;
	case 'j': // jump target
		switch (str[2]) {
		case 't':
			esil->jump_target = num;
			esil->jump_target_set = 1;
			break;
		case 's':
			esil->jump_target_set = num;
			break;
		default:
			return false;
		}
	default:
		return false;
	}
	return true;
}

R_API int r_anal_esil_get_parm_size(RAnalEsil *esil, const char *str, ut64 *num, int *size) {
	if (!str || !*str) {
		return false;
	}
	int parm_type = r_anal_esil_get_parm_type (esil, str);
	if (!num || !esil) {
		return false;
	}
	switch (parm_type) {
	case R_ANAL_ESIL_PARM_INTERNAL:
		// *num = esil_internal_read (esil, str, num);
		if (size) *size = esil->anal->bits;
		return esil_internal_read (esil, str, num);
	case R_ANAL_ESIL_PARM_NUM:
		*num = r_num_get (NULL, str);
		if (size) *size = esil->anal->bits;
		return true;
	case R_ANAL_ESIL_PARM_REG:
		if (!r_anal_esil_reg_read (esil, str, num, size)) {
			break;
		}
		return true;
	default:
		IFDBG eprintf ("Invalid arg (%s)\n", str);
		esil->parse_stop = 1;
		break;
	}
	return false;
}

R_API int r_anal_esil_get_parm(RAnalEsil *esil, const char *str, ut64 *num) {
	return r_anal_esil_get_parm_size (esil, str, num, NULL);
}

R_API int r_anal_esil_reg_write(RAnalEsil *esil, const char *dst, ut64 num) {
	int ret = 0;
	IFDBG { eprintf ("%s=0x%" PFMT64x "\n", dst, num); }
	if (esil && esil->cb.hook_reg_write) {
		ret = esil->cb.hook_reg_write (esil, dst, &num);
	}
	if (!ret && esil && dst[0] == ESIL_INTERNAL_PREFIX && dst[1]) {
		ret = esil_internal_write (esil, dst, num);
	}
	if (!ret && esil && esil->cb.reg_write) {
		ret = esil->cb.reg_write (esil, dst, num);
	}
	return ret;
}

R_API int r_anal_esil_reg_read_nocallback(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	int ret;
	void *old_hook_reg_read = (void *) esil->cb.hook_reg_read;

	esil->cb.hook_reg_read = NULL;
	ret = r_anal_esil_reg_read (esil, regname, num, size);
	esil->cb.hook_reg_read = old_hook_reg_read;

	return ret;
}

R_API int r_anal_esil_reg_read(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	bool ret = false;
	ut64 localnum; // XXX why is this necessary?
	if (!esil || !regname) {
		return false;
	}
	if (regname[0] == ESIL_INTERNAL_PREFIX && regname[1]) {
		if (size) {
			*size = esil->anal->bits;
		}
		return esil_internal_read (esil, regname, num);
	}
	if (!num) num = &localnum;
	*num = 0LL;
	if (size) *size = esil->anal->bits;
	if (esil->cb.hook_reg_read) {
		ret = esil->cb.hook_reg_read (esil, regname, num, size);
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read (esil, regname, num, size);
	}
	return ret;
}

static int esil_eq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);

	if (src && dst && r_anal_esil_reg_read_nocallback (esil, dst, &num, NULL)) {
		if (r_anal_esil_get_parm (esil, src, &num2)) {
			ret = r_anal_esil_reg_write (esil, dst, num2);
			if (ret && r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) { //necessary for some flag-things
				esil->cur = num2;
				esil->old = num;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
		} else {
			ERR ("esil_eq: invalid src");
		}
	} else {
		ERR ("esil_eq: invalid parameters");
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
			r_anal_esil_pushnum (esil, !num);
			ret = 1;
		} else {
			if (isregornum (esil, src, &num)) {
				ret = 1;
				r_anal_esil_pushnum (esil, !num);
			} else {
				eprintf ("0x%08"PFMT64x" esil_neg: unknown reg %s\n", esil->address, src);
			}
		}
	} else {
		ERR ("esil_neg: empty stack");
	}
	free (src);
	return ret;
}

static int esil_negeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 num;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_reg_read (esil, src, &num, NULL)) {
		num = !num;
		r_anal_esil_reg_write (esil, src, num);
		ret = 1;
	} else {
		ERR ("esil_negeq: empty stack");
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
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = num;
				esil->cur = num & num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, num & num2);
			ret = 1;
		} else {
			ERR ("esil_andeq: empty stack");
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
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = num;
				esil->cur = num | num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, num | num2);
			ret = 1;
		} else {
			ERR ("esil_ordeq: empty stack");
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
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = num;
				esil->cur = num ^ num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, num ^ num2);
			ret = 1;
		} else {
			ERR ("esil_xoreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

#if 0
static int esil_interrupt_linux_i386(RAnalEsil *esil) { 		//move this into a plugin
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

static int esil_trap(RAnalEsil *esil) {
	ut64 s, d;
	if (popRN (esil, &s) && popRN (esil, &d)) {
		esil->trap = s;
		esil->trap_code = d;
		return r_anal_esil_fire_trap (esil, (int)s, (int)d);
	}
	ERR ("esil_trap: missing parameters in stack");
	return false;
}

static int esil_bits(RAnalEsil *esil) {
	ut64 s;
	if (popRN (esil, &s)) {
		if (esil->anal && esil->anal->coreb.setab) {
			esil->anal->coreb.setab (esil->anal->coreb.core, NULL, s);
		}
		return true;
	}
	ERR ("esil_bits: missing parameters in stack");
	return false;
}

static int esil_interrupt(RAnalEsil *esil) {
	ut64 interrupt;
	if (popRN (esil, &interrupt)) {
		return r_anal_esil_fire_interrupt (esil, (int)interrupt);
	}
	return false;
}

// Pushes result onto stack. Pushes op1 == op2 onto stack, not the difference.
// This function also sets internal vars which is used in flag calculations.
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
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, num == num2);
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
static int esil_ifset(RAnalEsil *esil) {
	char *s, *src = r_anal_esil_pop (esil);
	for (s=src; *s; s++) {
		switch (*s) {
		case 'z':
			r_anal_esil_reg_write (esil, "zf", R_BIT_CHK(&esil->flags, FLG(ZERO)));
			break;
		case 'c':
			r_anal_esil_reg_write (esil, "cf", R_BIT_CHK(&esil->flags, FLG(CARRY)));
			break;
		case 'o':
			r_anal_esil_reg_write (esil, "of", R_BIT_CHK(&esil->flags, FLG(OVERFLOW)));
			break;
		case 'p':
			r_anal_esil_reg_write (esil, "pf", R_BIT_CHK(&esil->flags, FLG(PARITY)));
			break;
		}
	}
	free (src);
	return 0;
}
#endif

static int esil_if(RAnalEsil *esil) {
	ut64 num = 0LL;
	char *src = r_anal_esil_pop (esil);
	if (src) {
		// TODO: check return value
		(void)r_anal_esil_get_parm (esil, src, &num);
		// condition not matching, skipping until }
		if (!num) {
			esil->skip = true;
		}
		free (src);
		return true;
	}
	return false;
}

static int esil_lsl(RAnalEsil *esil) {
	int ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 res = num << num2;
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_lsl: empty stack");
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
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			num <<= num2;
			esil->cur = num;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			r_anal_esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			ERR ("esil_lsleq: empty stack");
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
			ut64 res = num >> num2;
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_lsr: empty stack");
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
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			num >>= num2;
			esil->cur = num;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			r_anal_esil_reg_write (esil, dst, num);
			ret = 1;
		} else {
			ERR ("esil_lsreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_asreq(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 op_num, param_num;
	char *op = r_anal_esil_pop (esil);
	char *param = r_anal_esil_pop (esil);
	if (op && r_anal_esil_get_parm_size (esil, op, &op_num, &regsize)) {
		if (param && r_anal_esil_get_parm (esil, param, &param_num)) {
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
					op_num = -op_num;
					if (op_num >> param_num) {
						op_num >>= param_num;
						op_num = -op_num;
					} else {
						op_num = -1;
					}
				} else {
					ut64 mask = (regsize - 1);
					param_num &= mask;
					ut64 left_bits = 0;
					if (op_num & (1 << (regsize - 1))) {
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
			r_anal_esil_reg_write (esil, op, res);
			// r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_asr: empty stack");
		}
	}
	free (param);
	free (op);
	return ret;
}

static int esil_asr(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 op_num, param_num;
	char *op    = r_anal_esil_pop (esil);
	char *param = r_anal_esil_pop (esil);
	if (op && r_anal_esil_get_parm_size (esil, op, &op_num, &regsize)) {
		if (param && r_anal_esil_get_parm (esil, param, &param_num)) {
			bool isNegative;
			if (regsize == 32) {
				isNegative = ((st32)op_num)<0;
				st32 snum = op_num;
				op_num = snum;
			} else {
				isNegative = ((st64)op_num)<0;
			}
			if (isNegative) {
				ut64 mask = (regsize - 1);
				param_num &= mask;
				ut64 left_bits = 0;
				if (op_num & (1 << (regsize - 1))) {
					left_bits = (1 << param_num) - 1;
					left_bits <<= regsize - param_num;
				}
				op_num = left_bits | (op_num >> param_num);
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_asr: empty stack");
		}
	}
	free (param);
	free (op);
	return ret;
}

static int esil_ror(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num >> num2) | (num << ((-num2) & mask));
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_ror: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_rol(RAnalEsil *esil) {
	int regsize, ret = 0;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num << num2) | (num >> ((-num2) & mask));
			r_anal_esil_pushnum (esil, res);
			ret = 1;
		} else {
			ERR ("esil_rol: empty stack");
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
			ERR ("esil_and: empty stack");
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
			ERR ("esil_xor: empty stack");
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
			ERR ("esil_xor: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

R_API const char *r_anal_esil_trapstr(int type) {
	switch (type) {
	case R_ANAL_TRAP_READ_ERR:
		return "read-err";
	case R_ANAL_TRAP_WRITE_ERR:
		return "write-err";
	case R_ANAL_TRAP_BREAKPOINT:
		return "breakpoint";
	case R_ANAL_TRAP_UNHANDLED:
		return "unhandled";
	case R_ANAL_TRAP_DIVBYZERO:
		return "divbyzero";
	default:
		return "unknown";
	}
}

R_API int r_anal_esil_dumpstack(RAnalEsil *esil) {
	int i;
	if (!esil) {
		return 0;
	}
	if (esil->trap) {
		eprintf ("ESIL TRAP type %d code 0x%08x %s\n",
			esil->trap, esil->trap_code,
			r_anal_esil_trapstr (esil->trap));
	}
	if (esil->stackptr < 1) {
		return 0;
	}
	for (i = esil->stackptr - 1; i >= 0; i--) {
		esil->anal->cb_printf ("%s\n", esil->stack[i]);
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

static int esil_repeat(RAnalEsil *esil) {
	char *dst = r_anal_esil_pop (esil); // destaintion of the goto
	char *src = r_anal_esil_pop (esil); // value of the counter
	ut64 n, num = 0;
	if (r_anal_esil_get_parm (esil, src, &n) && r_anal_esil_get_parm (esil, dst, &num)) {
		if (n > 1) {
			esil->parse_goto = num;
			r_anal_esil_pushnum (esil, n - 1);
		}
	}
	free (dst);
	free (src);
	return 1;
}

static int esil_pop(RAnalEsil *esil) {
	char *dst = r_anal_esil_pop (esil);
	free (dst);
	return 1;
}

static int esil_mod(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			if (s == 0) {
				if (esil->verbose > 0) {
					eprintf ("0x%08"PFMT64x" esil_mod: Division by zero!\n", esil->address);
				}
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_anal_esil_pushnum (esil, d % s);
			}
			ret = 1;
		}
	} else {
		ERR ("esil_mod: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_modeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
					esil->old = d;
					esil->cur = d % s;
					esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				}
				r_anal_esil_reg_write (esil, dst, d % s);
			} else {
				ERR ("esil_modeq: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = 1;
		} else {
			ERR ("esil_modeq: empty stack");
		}
	} else {
		ERR ("esil_modeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_div(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			if (s == 0) {
				ERR ("esil_div: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_anal_esil_pushnum (esil, d / s);
			}
			ret = 1;
		}
	} else {
		ERR ("esil_div: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_diveq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
					esil->old = d;
					esil->cur = d / s;
					esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				}
				r_anal_esil_reg_write (esil, dst, d / s);
			} else {
				// eprintf ("0x%08"PFMT64x" esil_diveq: Division by zero!\n", esil->address);
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = 1;
		} else {
			ERR ("esil_diveq: empty stack");
		}
	} else {
		ERR ("esil_diveq: invalid parameters");
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
			r_anal_esil_pushnum (esil, d * s);
			ret = 1;
		} else {
			ERR ("esil_mul: empty stack");
		}
	} else {
		ERR ("esil_mul: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_muleq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = d;
				esil->cur = d * s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, s * d);
			ret = true;
		} else {
			ERR ("esil_muleq: empty stack");
		}
	} else {
		ERR ("esil_muleq: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_add(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, s + d);
			ret = true;
		}
	} else {
		ERR ("esil_add: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_addeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = d;
				esil->cur = d + s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, s + d);
			ret = true;
		}
	} else {
		ERR ("esil_addeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_inc(RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s++;
		r_anal_esil_pushnum (esil, s);
		ret = true;
	} else {
		ERR ("esil_inc: invalid parameters");
	}
	free (src);
	return ret;
}

static int esil_inceq(RAnalEsil *esil) {
	int ret = 0;
	ut64 sd;
	char *src_dst = r_anal_esil_pop (esil);
	if (src_dst && (r_anal_esil_get_parm_type (esil, src_dst) == R_ANAL_ESIL_PARM_REG) && r_anal_esil_get_parm (esil, src_dst, &sd)) {
		// inc rax
		esil->old = sd++;
		esil->cur = sd;
		r_anal_esil_reg_write (esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg (esil, src_dst);
		ret = true;
	} else {
		ERR ("esil_inceq: invalid parameters");
	}
	free (src_dst);
	return ret;
}

static int esil_sub(RAnalEsil *esil) {
	ut64 s = 0, d = 0;
	char * dst = r_anal_esil_pop (esil);
	if (!dst) {
		goto dst_broken;
	}
	if (r_anal_esil_reg_read (esil, dst, &d, NULL)) {
		esil->lastsz = esil_internal_sizeof_reg (esil, dst);
	} else {
		if (!isnum (esil, dst, &d)) {
			free (dst);
			goto dst_broken;
		}
		esil->lastsz = 64;
	}
	free (dst);

	if (!popRN (esil, &s)) {
		ERR ("esil_sub: src is broken");
		return false;
	}
	esil->old = d;
	esil->cur = d - s;
	r_anal_esil_pushnum (esil, esil->cur);
	return true;

dst_broken:
	ERR ("esil_sub: dst is broken");
	return false;
}

static int esil_subeq(RAnalEsil *esil) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_INTERNAL) {
				esil->old = d;
				esil->cur = d - s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			}
			r_anal_esil_reg_write (esil, dst, d - s);
			ret = true;
		}
	} else {
		ERR ("esil_subeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_dec(RAnalEsil *esil) {
	int ret = 0;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s--;
		r_anal_esil_pushnum (esil, s);
		ret = true;
	} else {
		ERR ("esil_dec: invalid parameters");
	}
	free (src);
	return ret;
}

static int esil_deceq(RAnalEsil *esil) {
	int ret = 0;
	ut64 sd;
	char *src_dst = r_anal_esil_pop (esil);
	if (src_dst && (r_anal_esil_get_parm_type (esil, src_dst) == R_ANAL_ESIL_PARM_REG) && r_anal_esil_get_parm (esil, src_dst, &sd)) {
		esil->old = sd;
		sd--;
		esil->cur = sd;
		r_anal_esil_reg_write (esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg (esil, src_dst);
		ret = true;
	} else {
		ERR ("esil_deceq: invalid parameters");
	}
	free (src_dst);
	return ret;
}

/* POKE */
static int esil_poke_n(RAnalEsil *esil, int bits) {
	ut64 bitmask = genmask (bits - 1);
	ut64 num, addr;
	ut8 b[8] = {0};
	ut64 n;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	int bytes = R_MIN (sizeof (b), bits / 8), ret = 0;
	if (bits % 8) {
		free (src);
		free (dst);
		return 0;
	}
	//eprintf ("GONA POKE %d src:%s dst:%s\n", bits, src, dst);
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &addr)) {
			int type = r_anal_esil_get_parm_type (esil, src);
			if (type != R_ANAL_ESIL_PARM_INTERNAL) {
				r_anal_esil_mem_read (esil, addr, b, bytes);
				n = r_read_ble64 (b, esil->anal->big_endian);
				esil->old = n;
				esil->cur = num;
				esil->lastsz = bits;
				num = num & bitmask;
			}
			r_write_ble (b, num, esil->anal->big_endian, bits);
			ret = r_anal_esil_mem_write (esil, addr, b, bytes);
		}
	}
	free (src);
	free (dst);
	return ret;
}

static int esil_poke1(RAnalEsil *esil) {
	return esil_poke_n (esil, 8);
}
static int esil_poke2(RAnalEsil *esil) {
	return esil_poke_n (esil, 16);
}
static int esil_poke3(RAnalEsil *esil) {
	return esil_poke_n (esil, 24);
}
static int esil_poke4(RAnalEsil *esil) {
	return esil_poke_n (esil, 32);
}
static int esil_poke8(RAnalEsil *esil) {
	return esil_poke_n (esil, 64);
}
static int esil_poke(RAnalEsil *esil) {
	return esil_poke_n (esil, esil->anal->bits);
}

static int esil_poke_some(RAnalEsil *esil) {
	int i, ret = 0;
	int regsize;
	ut64 ptr, regs = 0, tmp;
	char *count, *dst = r_anal_esil_pop (esil);
#define BYTES_SIZE 64
	if (dst && r_anal_esil_get_parm_size (esil, dst, &tmp, &regsize)) {
		// reg
		isregornum (esil, dst, &ptr);
		count = r_anal_esil_pop (esil);
		if (count) {
			isregornum (esil, count, &regs);
			if (regs > 0) {
				ut8 b[BYTES_SIZE];
				ut64 num64;
				for (i = 0; i < regs; i++) {
					char *foo = r_anal_esil_pop (esil);
					if (!foo) {
						// avoid looping out of stack
						free (dst);
						free (count);
						return 1;
					}
					isregornum (esil, foo, &num64);
					/* TODO: implement peek here */
					// read from $dst
					r_write_ble (b, num64, esil->anal->big_endian, regsize);
					ret = r_anal_esil_mem_write (esil, ptr, b, BYTES_SIZE);
					if (ret != BYTES_SIZE) {
						//eprintf ("Cannot write at 0x%08" PFMT64x "\n", ptr);
						esil->trap = 1;
					}
					ptr += BYTES_SIZE;
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

/* PEEK */

static int esil_peek_n(RAnalEsil *esil, int bits) {
	char res[32];
	ut64 addr;
	int ret = 0, bytes = bits / 8;
	char *dst = r_anal_esil_pop (esil);
	if (bits & 7) {
		free (dst);
		return 0;
	}
	//eprintf ("GONA PEEK %d dst:%s\n", bits, dst);
	if (dst && isregornum (esil, dst, &addr)) {
		ut64 bitmask = genmask (bits - 1);
		ut8 a[sizeof(ut64)] = {0};
		ret = r_anal_esil_mem_read (esil, addr, a, bytes);
		ut64 b = r_read_ble64 (a, 0); //esil->anal->big_endian);
		if (esil->anal->big_endian) {
			r_mem_swapendian ((ut8*)&b, (const ut8*)&b, bytes);
		}
		snprintf (res, sizeof (res), "0x%" PFMT64x, b & bitmask);
		r_anal_esil_push (esil, res);
		esil->lastsz = bits;
	}
	free (dst);
	return ret;
}

static int esil_peek1(RAnalEsil *esil) {
	return esil_peek_n (esil, 8);
}
static int esil_peek2(RAnalEsil *esil) {
	return esil_peek_n (esil, 16);
}
static int esil_peek3(RAnalEsil *esil) {
	return esil_peek_n (esil, 24);
}
static int esil_peek4(RAnalEsil *esil) {
	return esil_peek_n (esil, 32);
}
static int esil_peek8(RAnalEsil *esil) {
	return esil_peek_n (esil, 64);
}
static int esil_peek(RAnalEsil *esil) {
	return esil_peek_n (esil, esil->anal->bits);
};

static int esil_peek_some(RAnalEsil *esil) {
	int i, ret = 0;
	ut64 ptr, regs;
	// pop ptr
	char *count, *dst = r_anal_esil_pop (esil);
	if (dst) {
		// reg
		isregornum (esil, dst, &ptr);
		count = r_anal_esil_pop (esil);
		if (count) {
			isregornum (esil, count, &regs);
			if (regs > 0) {
				ut32 num32;
				ut8 a[sizeof (ut32)];
				for (i = 0; i < regs; i++) {
					char *foo = r_anal_esil_pop (esil);
					if (!foo) {
						ERR ("Cannot pop in peek");
						return 0;
					}
					ret = r_anal_esil_mem_read (esil, ptr, a, 4);
					if (ret == sizeof (ut32)) {
						num32 = r_read_ble32 (a, esil->anal->big_endian);
						r_anal_esil_reg_write (esil, foo, num32);
					} else {
						if (esil->verbose) {
							eprintf ("Cannot peek from 0x%08" PFMT64x "\n", ptr);
						}
					}
					ptr += sizeof (ut32);
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

static int esil_mem_oreq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);  //save the dst-addr
	char *src0 = r_anal_esil_pop (esil); //get the src
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) { 	//get the src
		r_anal_esil_push (esil, dst);			//push the dst-addr
		ret = (!!esil_peek_n (esil, bits));		//read
		src1 = r_anal_esil_pop (esil);			//get the old dst-value
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) { //get the old dst-value
			d |= s;					//calculate the new dst-value
			r_anal_esil_pushnum (esil, d);		//push the new dst-value
			r_anal_esil_push (esil, dst);		//push the dst-addr
			ret &= (!!esil_poke_n (esil, bits));	//write
		} else ret = 0;
	}
	if (!ret) {
		ERR ("esil_mem_oreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_oreq1(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 8);
}
static int esil_mem_oreq2(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 16);
}
static int esil_mem_oreq4(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 32);
}
static int esil_mem_oreq8(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 64);
}
static int esil_mem_oreq(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, esil->anal->bits);
}

/* XOREQ */

static int esil_mem_xoreq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d ^= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret) {
		ERR ("esil_mem_xoreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_xoreq1(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 8);
}
static int esil_mem_xoreq2(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 16);
}
static int esil_mem_xoreq4(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 32);
}
static int esil_mem_xoreq8(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 64);
}
static int esil_mem_xoreq(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, esil->anal->bits);
}

/* ANDEQ */

static int esil_mem_andeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d &= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret) {
		ERR ("esil_mem_andeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_andeq1(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 8);
}
static int esil_mem_andeq2(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 16);
}
static int esil_mem_andeq4(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 32);
}
static int esil_mem_andeq8(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 64);
}
static int esil_mem_andeq(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, esil->anal->bits);
}

/* ADDEQ */

static int esil_mem_addeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d += s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_addeq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_addeq1(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 8);
}
static int esil_mem_addeq2(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 16);
}
static int esil_mem_addeq4(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 32);
}
static int esil_mem_addeq8(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 64);
}
static int esil_mem_addeq(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, esil->anal->bits);
}

/* SUBEQ */

static int esil_mem_subeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d -= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_subeq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_subeq1(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 8);
}
static int esil_mem_subeq2(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 16);
}
static int esil_mem_subeq4(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 32);
}
static int esil_mem_subeq8(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 64);
}
static int esil_mem_subeq(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, esil->anal->bits);
}

/* MODEQ */

static int esil_mem_modeq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		if (s == 0) {
			ERR ("esil_mem_modeq4: Division by zero!");
			esil->trap = R_ANAL_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			r_anal_esil_push (esil, dst);
			ret = (!!esil_peek_n (esil, bits));
			src1 = r_anal_esil_pop (esil);
			if (src1 && r_anal_esil_get_parm (esil, src1, &d) && s >= 1) {
				r_anal_esil_pushnum (esil, d % s);
				d = d % s;
				r_anal_esil_pushnum (esil, d);
				r_anal_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else {
				ret = 0;
			}
		}
	}
	if (!ret) {
		ERR ("esil_mem_modeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_modeq1(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 8);
}
static int esil_mem_modeq2(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 16);
}
static int esil_mem_modeq4(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 32);
}
static int esil_mem_modeq8(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 64);
}
static int esil_mem_modeq(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, esil->anal->bits);
}

/* DIVEQ */

static int esil_mem_diveq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		if (s == 0) {
			ERR ("esil_mem_diveq8: Division by zero!");
			esil->trap = R_ANAL_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			r_anal_esil_push (esil, dst);
			ret = (!!esil_peek_n (esil, bits));
			src1 = r_anal_esil_pop (esil);
			if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
				d = d / s;
				r_anal_esil_pushnum (esil, d);
				r_anal_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else ret = 0;
		}
	}
	if (!ret)
		ERR ("esil_mem_diveq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_diveq1(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 8);
}
static int esil_mem_diveq2(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 16);
}
static int esil_mem_diveq4(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 32);
}
static int esil_mem_diveq8(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 64);
}
static int esil_mem_diveq(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, esil->anal->bits);
}

/* MULEQ */

static int esil_mem_muleq_n(RAnalEsil *esil, int bits, ut64 bitmask) {
	int ret = 0;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d *= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_muleq_n: invalid parameters");
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static int esil_mem_muleq1(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 8, UT8_MAX);
}
static int esil_mem_muleq2(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 16, UT16_MAX);
}
static int esil_mem_muleq4(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 32, UT32_MAX);
}
static int esil_mem_muleq8(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 64, UT64_MAX);
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

/* INCEQ */

static int esil_mem_inceq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		r_anal_esil_push (esil, off);
		ret = (!!esil_peek_n (esil, bits));
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s++;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_inceq_n: invalid parameters");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_inceq1(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 8);
}
static int esil_mem_inceq2(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 16);
}
static int esil_mem_inceq4(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 32);
}
static int esil_mem_inceq8(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 64);
}
static int esil_mem_inceq(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, esil->anal->bits);
}

/* DECEQ */

static int esil_mem_deceq_n(RAnalEsil *esil, int bits) {
	int ret = 0;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		r_anal_esil_push (esil, off);
		ret = (!!esil_peek_n (esil, bits));
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			s--;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= (!!esil_poke_n (esil, bits));
		} else ret = 0;
	}
	if (!ret)
		ERR ("esil_mem_deceq_n: invalid parameters");
	free (src);
	free (off);
	return ret;
}

static int esil_mem_deceq1(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 8);
}
static int esil_mem_deceq2(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 16);
}
static int esil_mem_deceq4(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 32);
}
static int esil_mem_deceq8(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 64);
}
static int esil_mem_deceq(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, esil->anal->bits);
}

/* get value of register or memory reference and push the value */
static int esil_num(RAnalEsil *esil) {
	char *dup_me;
	ut64 dup;
	if (!esil)
		return false;
	if (!(dup_me = r_anal_esil_pop (esil)))
		return false;
	if (!r_anal_esil_get_parm (esil, dup_me, &dup)) {
		free (dup_me);
		return false;
	}
	free (dup_me);
	return r_anal_esil_pushnum (esil, dup);
}

/* duplicate the last element in the stack */
static int esil_dup(RAnalEsil *esil) {
	if (!esil || !esil->stack || esil->stackptr < 1 || esil->stackptr > (esil->stacksize - 1))
		return false;
	return r_anal_esil_push (esil, esil->stack[esil->stackptr-1]);
}

static int esil_swap(RAnalEsil *esil) {
	char *tmp;
	if (!esil || !esil->stack || esil->stackptr < 2)
		return false;
	if (!esil->stack[esil->stackptr-1] || !esil->stack[esil->stackptr-2])
		return false;
	tmp = esil->stack[esil->stackptr-1];
	esil->stack[esil->stackptr-1] = esil->stack[esil->stackptr-2];
	esil->stack[esil->stackptr-2] = tmp;
	return true;
}

static int __esil_generic_pick(RAnalEsil *esil, int rev) {
	char *idx = r_anal_esil_pop (esil);
	ut64 i;
	int ret = false;
	if (!idx || !r_anal_esil_get_parm (esil, idx, &i)) {
		ERR ("esil_pick: invalid index number");
		goto end;
	}
	if (!esil || !esil->stack) {
		ERR ("esil_pick: stack not initialized");
		goto end;
	}
	if (rev) {
		i = esil->stackptr + (((st64) i) * -1);
	}
	if (esil->stackptr < i) {
		ERR ("esil_pick: index out of stack bounds");
		goto end;
	}
	if (!esil->stack[esil->stackptr-i]) {
		ERR ("esil_pick: undefined element");
		goto end;
	}
	if (!r_anal_esil_push (esil, esil->stack[esil->stackptr-i])) {
		ERR ("ESIL stack is full");
		esil->trap = 1;
		esil->trap_code = 1;
		goto end;
	}
	ret = true;
end:
	free (idx);
	return ret;
}

static int esil_pick(RAnalEsil *esil) {
	return __esil_generic_pick (esil, 0);
}

static int esil_rpick(RAnalEsil *esil) {
	return __esil_generic_pick (esil, 1);
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

static int esil_smaller(RAnalEsil *esil) { // 'dst < src' => 'src,dst,<'
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, (num != num2) &
			                           !signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_bigger(RAnalEsil *esil) { // 'dst > src' => 'src,dst,>'
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_smaller_equal(RAnalEsil *esil) { // 'dst <= src' => 'src,dst,<='
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, !signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int esil_bigger_equal(RAnalEsil *esil) { // 'dst >= src' => 'src,dst,>='
	ut64 num, num2;
	int ret = 0;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = 1;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			r_anal_esil_pushnum (esil, (num == num2) |
			                           signed_compare_gt (num, num2, esil->lastsz));
		}
	}
	free (dst);
	free (src);
	return ret;
}

static int iscommand(RAnalEsil *esil, const char *word, RAnalEsilOp *op) {
	char t[128];
	char *h;
	h = sdb_itoa (sdb_hash (word), t, 16);
	if (sdb_num_exists (esil->ops, h)) {
		*op = (RAnalEsilOp)(size_t)sdb_num_get (esil->ops, h, 0);
		return true;
	}
	return false;
}

static int runword(RAnalEsil *esil, const char *word) {
	RAnalEsilOp op = NULL;
	if (!word) {
		return 0;
	}
	esil->parse_goto_count--;
	if (esil->parse_goto_count < 1) {
		ERR ("ESIL infinite loop detected\n");
		esil->trap = 1;       // INTERNAL ERROR
		esil->parse_stop = 1; // INTERNAL ERROR
		return 0;
	}

	// Don't push anything onto stack when processing if statements
	if (!strcmp (word, "?{") && esil->Reil) {
		esil->Reil->skip = esil->Reil->skip? 0: 1;
		if (esil->Reil->skip) {
			esil->Reil->cmd_count = 0;
			memset (esil->Reil->if_buf, 0, sizeof (esil->Reil->if_buf));
		}
	}

	if (esil->Reil && esil->Reil->skip) {
		int tmp_len = strlen (esil->Reil->if_buf);
		strncat (esil->Reil->if_buf, word, sizeof (esil->Reil->if_buf) - tmp_len - 2);
		strncat (esil->Reil->if_buf, ",", 1);
		if (!strcmp (word, "}")) {
			r_anal_esil_pushnum (esil, esil->Reil->addr + esil->Reil->cmd_count + 1);
			r_anal_esil_parse (esil, esil->Reil->if_buf);
			return 1;
		}
		if (iscommand (esil, word, &op)) esil->Reil->cmd_count++;
		return 1;
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
			if (esil->cb.hook_command) {
				if (esil->cb.hook_command (esil, word)) {
					return 1; // XXX cannot return != 1
				}
			}
			return op (esil);
		}
	}
	if (!*word || *word == ',') {
		// skip empty words
		return 1;
	}

	// push value
	if (!r_anal_esil_push (esil, word)) {
		ERR ("ESIL stack is full");
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
			ostr = str + 1;
			count++;
		}
	}
	return NULL;
}

/** evaluate an esil word and return the action to perform
 * TODO: Use `enum` here
 * 0: continue running the
 * 1: stop execution
 * 2: continue in loop
 * 3: normal continuation
 */
static int evalWord(RAnalEsil *esil, const char *ostr, const char **str) {
	if (!esil || !str || !*str) {
		return 0;
	}
	if ((*str)[0] && (*str)[1] == ',') {
		return 2;
	}
	if (esil->repeat) {
		return 0;
	}
	if (esil->parse_goto != -1) {
		// TODO: detect infinite loop??? how??
		*str = gotoWord (ostr, esil->parse_goto);
		if (*str) {
			esil->parse_goto = -1;
			return 2;
		}
		if (esil->verbose) {
			eprintf ("Cannot find word %d\n", esil->parse_goto);
		}
		return 1;
	}
	if (esil->parse_stop) {
		if (esil->parse_stop == 2) {
			eprintf ("ESIL TODO: %s\n", *str + 1);
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
	if (!esil || !str || !*str) {
		return 0;
	}
	esil->trap = 0;
	if (esil->cmd && esil->cmd_todo) {
		if (!strncmp (str, "TODO", 4)) {
			esil->cmd (esil, esil->cmd_todo, esil->address, 0);
		}
	}
loop:
	esil->repeat = 0;
	esil->skip = 0;
	esil->parse_goto = -1;
	esil->parse_stop = 0;
	if (esil->anal) {
		esil->parse_goto_count = esil->anal->esil_goto_limit;
	} else {
		esil->parse_goto_count = R_ANAL_ESIL_GOTO_LIMIT;
	}
	str = ostr;
repeat:
	wordi = 0;
	while (*str) {
		if (wordi > 62) {
			ERR ("Invalid esil string");
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
			if (*word) {
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
				if (dorunword == 1) {
					return 0;
				}
			}
			str++;
		}
		word[wordi++] = *str;
		//is *str is '\0' in the next iteration the condition will be true
		//reading beyond the boundaries
		if (*str) str++;
	}
	word[wordi] = 0;
	if (*word) {
		if (!runword (esil, word)) {
			return 0;
		}
		switch (evalWord (esil, ostr, &str)) {
		case 0: goto loop;
		case 1: return 0;
		case 2: goto repeat;
		}
	}
	return 1;
}

R_API int r_anal_esil_runword(RAnalEsil *esil, const char *word) {
	const char *str = NULL;
	runword (esil, word);
	if (*word) {
		if (!runword (esil, word)) {
			return 0;
		}
		int ew = evalWord (esil, word, &str);
		eprintf ("ew %d\n", ew);
		eprintf ("--> %s\n", r_str_get (str));
	}
	return 1;
}

//frees all elements from the stack, not the stack itself
//rename to stack_empty() ?
R_API void r_anal_esil_stack_free(RAnalEsil *esil) {
	int i;
	if (esil) {
		for (i = 0; i < esil->stackptr; i++) {
			R_FREE (esil->stack[i]);
		}
		esil->stackptr = 0;
	}
}

R_API int r_anal_esil_condition(RAnalEsil *esil, const char *str) {
	char *popped;
	int ret;
	if (!esil) {
		return false;
	}
	while (*str == ' ') str++; // use proper string chop?
	(void) r_anal_esil_parse (esil, str);
	popped = r_anal_esil_pop (esil);
	if (popped) {
		ut64 num;
		if (isregornum (esil, popped, &num)) {
			ret = !!num;
		} else {
			ret = 0;
		}
		free (popped);
	} else {
		ERR ("ESIL stack is empty");
		return -1;
	}
	return ret;
}

static void r_anal_esil_setup_ops(RAnalEsil *esil) {
#define OP(x, y) r_anal_esil_set_op (esil, x, y)
	OP ("$", esil_interrupt);
	OP ("==", esil_cmp);
	OP ("<", esil_smaller);
	OP (">", esil_bigger);
	OP ("<=", esil_smaller_equal);
	OP (">=", esil_bigger_equal);
	OP ("?{", esil_if);
	OP ("<<", esil_lsl);
	OP ("<<=", esil_lsleq);
	OP (">>", esil_lsr);
	OP (">>=", esil_lsreq);
	OP (">>>>", esil_asr);
	OP (">>>>=", esil_asreq);
	OP (">>>", esil_ror);
	OP ("<<<", esil_rol);
	OP ("&", esil_and);
	OP ("&=", esil_andeq);
	OP ("}", esil_nop); // just to avoid push
	OP ("|", esil_or);
	OP ("|=", esil_oreq);
	OP ("!", esil_neg);
	OP ("!=", esil_negeq);
	OP ("=", esil_eq);
	OP ("*", esil_mul);
	OP ("*=", esil_muleq);
	OP ("^", esil_xor);
	OP ("^=", esil_xoreq);
	OP ("+", esil_add);
	OP ("+=", esil_addeq);
	OP ("++", esil_inc);
	OP ("++=", esil_inceq);
	OP ("-", esil_sub);
	OP ("-=", esil_subeq);
	OP ("--", esil_dec);
	OP ("--=", esil_deceq);
	OP ("/", esil_div);
	OP ("/=", esil_diveq);
	OP ("%", esil_mod);
	OP ("%=", esil_modeq);
	OP ("=[]", esil_poke);
	OP ("=[1]", esil_poke1);
	OP ("=[2]", esil_poke2);
	OP ("=[3]", esil_poke3);
	OP ("=[4]", esil_poke4);
	OP ("=[8]", esil_poke8);
	OP ("|=[]", esil_mem_oreq);
	OP ("|=[1]", esil_mem_oreq1);
	OP ("|=[2]", esil_mem_oreq2);
	OP ("|=[4]", esil_mem_oreq4);
	OP ("|=[8]", esil_mem_oreq8);
	OP ("^=[]", esil_mem_xoreq);
	OP ("^=[1]", esil_mem_xoreq1);
	OP ("^=[2]", esil_mem_xoreq2);
	OP ("^=[4]", esil_mem_xoreq4);
	OP ("^=[8]", esil_mem_xoreq8);
	OP ("&=[]", esil_mem_andeq);
	OP ("&=[1]", esil_mem_andeq1);
	OP ("&=[2]", esil_mem_andeq2);
	OP ("&=[4]", esil_mem_andeq4);
	OP ("&=[8]", esil_mem_andeq8);
	OP ("+=[]", esil_mem_addeq);
	OP ("+=[1]", esil_mem_addeq1);
	OP ("+=[2]", esil_mem_addeq2);
	OP ("+=[4]", esil_mem_addeq4);
	OP ("+=[8]", esil_mem_addeq8);
	OP ("-=[]", esil_mem_subeq);
	OP ("-=[1]", esil_mem_subeq1);
	OP ("-=[2]", esil_mem_subeq2);
	OP ("-=[4]", esil_mem_subeq4);
	OP ("-=[8]", esil_mem_subeq8);
	OP ("%=[]", esil_mem_modeq);
	OP ("%=[1]", esil_mem_modeq1);
	OP ("%=[2]", esil_mem_modeq2);
	OP ("%=[4]", esil_mem_modeq4);
	OP ("%=[8]", esil_mem_modeq8);
	OP ("/=[]", esil_mem_diveq);
	OP ("/=[1]", esil_mem_diveq1);
	OP ("/=[2]", esil_mem_diveq2);
	OP ("/=[4]", esil_mem_diveq4);
	OP ("/=[8]", esil_mem_diveq8);
	OP ("*=[]", esil_mem_muleq);
	OP ("*=[1]", esil_mem_muleq1);
	OP ("*=[2]", esil_mem_muleq2);
	OP ("*=[4]", esil_mem_muleq4);
	OP ("*=[8]", esil_mem_muleq8);
	OP ("++=[]", esil_mem_inceq);
	OP ("++=[1]", esil_mem_inceq1);
	OP ("++=[2]", esil_mem_inceq2);
	OP ("++=[4]", esil_mem_inceq4);
	OP ("++=[8]", esil_mem_inceq8);
	OP ("--=[]", esil_mem_deceq);
	OP ("--=[1]", esil_mem_deceq1);
	OP ("--=[2]", esil_mem_deceq2);
	OP ("--=[4]", esil_mem_deceq4);
	OP ("--=[8]", esil_mem_deceq8);
	OP ("[]", esil_peek);
	OP ("[*]", esil_peek_some);
	OP ("=[*]", esil_poke_some);
	OP ("[1]", esil_peek1);
	OP ("[2]", esil_peek2);
	OP ("[3]", esil_peek3);
	OP ("[4]", esil_peek4);
	OP ("[8]", esil_peek8);
	OP ("STACK", r_anal_esil_dumpstack);
	OP ("REPEAT", esil_repeat);
	OP ("POP", esil_pop);
	OP ("TODO", esil_todo);
	OP ("GOTO", esil_goto);
	OP ("BREAK", esil_break);
	OP ("CLEAR", esil_clear);
	OP ("DUP", esil_dup);
	OP ("NUM", esil_num);
	OP ("PICK", esil_pick);
	OP ("RPICK", esil_rpick);
	OP ("SWAP", esil_swap);
	OP ("TRAP", esil_trap);
	OP ("BITS", esil_bits);
}

/* register callbacks using this anal module. */
R_API int r_anal_esil_setup(RAnalEsil *esil, RAnal *anal, int romem, int stats, int nonull) {
	if (!esil) return false;
	//esil->debug = 0;
	esil->anal = anal;
	esil->parse_goto_count = anal->esil_goto_limit;
	esil->trap = 0;
	esil->trap_code = 0;
	//esil->user = NULL;
	esil->cb.reg_read = internal_esil_reg_read;
	esil->cb.mem_read = internal_esil_mem_read;

	if (nonull) {
		// never writes zero to PC, BP, SP, why? because writing
		// zeros to these registers is equivalent to acessing NULL
		// pointer somehow
		esil->cb.reg_write = internal_esil_reg_write_no_null;
		esil->cb.mem_read = internal_esil_mem_read_no_null;
		esil->cb.mem_write = internal_esil_mem_write_no_null;

	} else {
		esil->cb.reg_write = internal_esil_reg_write;
		esil->cb.mem_read = internal_esil_mem_read;
		esil->cb.mem_write = internal_esil_mem_write;
	}
	r_anal_esil_mem_ro (esil, romem);
	r_anal_esil_stats (esil, stats);
	r_anal_esil_setup_ops (esil);

	if (anal->cur && anal->cur->esil_init && anal->cur->esil_fini) {
		return anal->cur->esil_init (esil);
	}
	return true;
}
