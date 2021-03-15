/* radare - LGPL - Copyright 2014-2021 - pancake, condret */

#include <r_anal.h>
#include <r_types.h>
#include <r_util.h>
#include <r_bind.h>

// should these be here?
#include <math.h>
#include <float.h>
#include <fenv.h>

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

/* Returns the number that has bits + 1 least significant bits set. */
static inline ut64 genmask(int bits) {
	ut64 m = UT64_MAX;
	if (bits > 0 && bits < 64) {
		m = (ut64)(((ut64)(2) << bits) - 1);
		if (!m) {
			m = UT64_MAX;
		}
	}
	return m;
}

#define ERR(x) if (esil->verbose) { eprintf ("%s\n", x); }

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

static bool ispackedreg(RAnalEsil *esil, const char *str) {
	RRegItem *ri = r_reg_get (esil->anal->reg, str, -1);
	return ri? ri->packed_size > 0: false;
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

static void esil_ops_free(HtPPKv *kv) {
	free (kv->key);
	free (kv->value);
}

R_API RAnalEsil *r_anal_esil_new(int stacksize, int iotrap, unsigned int addrsize) {
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
	esil->ops = ht_pp_new (NULL, esil_ops_free, NULL);
	esil->iotrap = iotrap;
	r_anal_esil_handlers_init (esil);
	r_anal_esil_plugins_init (esil);
	esil->addrmask = genmask (addrsize - 1);
	return esil;
}

R_API bool r_anal_esil_set_op(RAnalEsil *esil, const char *op, RAnalEsilOpCb code, ut32 push, ut32 pop, ut32 type) {
	r_return_val_if_fail (code && R_STR_ISNOTEMPTY (op) && esil && esil->ops, false);
	RAnalEsilOp *eop = ht_pp_find (esil->ops, op, NULL);
	if (!eop) {
		eop = R_NEW (RAnalEsilOp);
		if (!eop) {
			eprintf ("Cannot allocate esil-operation %s\n", op);
			return false;
		}
		if (!ht_pp_insert (esil->ops, op, eop)) {
			eprintf ("Cannot set esil-operation %s\n", op);
			free (eop);
			return false;
		}
	}
	eop->push = push;
	eop->pop = pop;
	eop->type = type;
	eop->code = code;
	return true;
}

R_API RAnalEsilOp *r_anal_esil_get_op(RAnalEsil *esil, const char *op) {
	r_return_val_if_fail (esil && esil->ops && R_STR_ISNOTEMPTY (op), NULL);
	return (RAnalEsilOp *) ht_pp_find (esil->ops, op, NULL);
}

R_API void r_anal_esil_del_op(RAnalEsil *esil, const char *op) {
	r_return_if_fail (esil && esil->ops && R_STR_ISNOTEMPTY (op));
	ht_pp_delete (esil->ops, op);
}

static bool r_anal_esil_fire_trap(RAnalEsil *esil, int trap_type, int trap_code) {
	r_return_val_if_fail (esil, false);
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
	r_anal_esil_plugins_fini (esil);
	r_anal_esil_handlers_fini (esil);
	ht_pp_free (esil->ops);
	esil->ops = NULL;
	sdb_free (esil->stats);
	esil->stats = NULL;
	r_anal_esil_stack_free (esil);
	free (esil->stack);
	if (esil->anal && esil->anal->cur && esil->anal->cur->esil_fini) {
		esil->anal->cur->esil_fini (esil);
	}
	r_anal_esil_trace_free (esil->trace);
	esil->trace = NULL;
	free (esil->cmd_intr);
	free (esil->cmd_trap);
	free (esil->cmd_mdev);
	free (esil->cmd_todo);
	free (esil->cmd_step);
	free (esil->cmd_step_out);
	free (esil->cmd_ioer);
	free (esil);
}

static ut8 esil_internal_sizeof_reg(RAnalEsil *esil, const char *r) {
	r_return_val_if_fail (esil && esil->anal && esil->anal->reg && r, 0);
	RRegItem *ri = r_reg_get (esil->anal->reg, r, -1);
	return ri? ri->size: 0;
}

static bool alignCheck(RAnalEsil *esil, ut64 addr) {
	int dataAlign = r_anal_archinfo (esil->anal, R_ANAL_ARCHINFO_DATA_ALIGN);
	return !(dataAlign > 0 && addr % dataAlign);
}

static bool internal_esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (esil && esil->anal && esil->anal->iob.io, 0);

	addr &= esil->addrmask;
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	if (esil->cmd_mdev && esil->mdev_range) {
		if (r_str_range_in (esil->mdev_range, addr)) {
			if (esil->cmd (esil, esil->cmd_mdev, addr, 0)) {
				return true;
			}
		}
	}
	//TODO: Check if error return from read_at.(on previous version of r2 this call always return len)
	(void)esil->anal->iob.read_at (esil->anal->iob.io, addr, buf, len);
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, read_at return true/false can't be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd (esil, esil->cmd_ioer, esil->address, 0);
		}
	}
	return len;
}

static bool internal_esil_mem_read_no_null(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (esil && esil->anal && esil->anal->iob.io, 0);

	addr &= esil->addrmask;
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	//TODO: Check if error return from read_at.(on previous version of r2 this call always return len)
	(void)esil->anal->iob.read_at (esil->anal->iob.io, addr, buf, len);
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, read_at return true/false can't be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
	}
	return len;
}

R_API bool r_anal_esil_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil, 0);
	bool ret = false;
	addr &= esil->addrmask;
	if (esil->cb.hook_mem_read) {
		ret = esil->cb.hook_mem_read (esil, addr, buf, len);
	}
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
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
		size_t i;
		eprintf ("0x%08" PFMT64x " R> ", addr);
		for (i = 0; i < len; i++) {
			eprintf ("%02x", buf[i]);
		}
		eprintf ("\n");
	}
	return ret;
}

static bool internal_esil_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret = 0;
	if (!esil || !esil->anal || !esil->anal->iob.io || esil->nowrite) {
		return 0;
	}
	addr &= esil->addrmask;
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	if (esil->cmd_mdev && esil->mdev_range) {
		if (r_str_range_in (esil->mdev_range, addr)) {
			if (esil->cmd (esil, esil->cmd_mdev, addr, 1)) {
				return true;
			}
		}
	}
	if (esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len)) {
		ret = len;
	}
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, write_at return true/false can't be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
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

static bool internal_esil_mem_write_no_null(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	bool ret = false;
	if (!esil || !esil->anal || !esil->anal->iob.io || !addr) {
		return false;
	}
	if (esil->nowrite) {
		return false;
	}
	addr &= esil->addrmask;
	if (esil->anal->iob.write_at (esil->anal->iob.io, addr, buf, len)) {
		ret = len;
	}
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, write_at return true/false can't be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (esil->anal->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
	}
	return ret;
}

R_API bool r_anal_esil_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	r_return_val_if_fail (esil && buf, false);
	int i, ret = 0;
	addr &= esil->addrmask;
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

static bool internal_esil_reg_read(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	if (reg) {
		if (size) {
			*size = reg->size;
		}
		if (num) {
			*num = r_reg_get_value (esil->anal->reg, reg);
		}
		return true;
	}
	return false;
}

static bool internal_esil_reg_write(RAnalEsil *esil, const char *regname, ut64 num) {
	if (esil && esil->anal) {
		RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
		if (reg) {
			r_reg_set_value (esil->anal->reg, reg, num);
			return true;
		}
	}
	return false;
}

//WTF IS THIS!!!
//Are you really trying to prevent the analyzed binary from doing anything that would cause it to segfault irl?
//WHY?
//	- condret
static bool internal_esil_reg_write_no_null (RAnalEsil *esil, const char *regname, ut64 num) {
	r_return_val_if_fail (esil && esil->anal && esil->anal->reg, false);

	RRegItem *reg = r_reg_get (esil->anal->reg, regname, -1);
	const char *pc = r_reg_get_name (esil->anal->reg, R_REG_NAME_PC);
	const char *sp = r_reg_get_name (esil->anal->reg, R_REG_NAME_SP);
	const char *bp = r_reg_get_name (esil->anal->reg, R_REG_NAME_BP);

	if (!pc) {
		eprintf ("Warning: RReg profile does not contain PC register\n");
		return false;
	}
	if (!sp) {
		eprintf ("Warning: RReg profile does not contain SP register\n");
		return false;
	}
	if (!bp) {
		eprintf ("Warning: RReg profile does not contain BP register\n");
		return false;
	}
	if (reg && reg->name && ((strcmp (reg->name , pc) && strcmp (reg->name, sp) && strcmp(reg->name, bp)) || num)) { //I trust k-maps
		r_reg_set_value (esil->anal->reg, reg, num);
		return true;
	}
	return false;
}

R_API bool r_anal_esil_pushnum(RAnalEsil *esil, ut64 num) {
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
	r_return_val_if_fail (esil, NULL);
	if (esil->stackptr < 1) {
		return NULL;
	}
	return esil->stack[--esil->stackptr];
}

R_API int r_anal_esil_get_parm_type(RAnalEsil *esil, const char *str) {
	int len, i;

	if (!str || !(len = strlen (str))) {
		return R_ANAL_ESIL_PARM_INVALID;
	}
	if (!strncmp (str, "0x", 2)) {
		return R_ANAL_ESIL_PARM_NUM;
	}
	if (!((IS_DIGIT (str[0])) || str[0] == '-')) {
		goto not_a_number;
	}
	for (i = 1; i < len; i++) {
		if (!(IS_DIGIT (str[i]))) {
			goto not_a_number;
		}
	}
	return R_ANAL_ESIL_PARM_NUM;
not_a_number:
	if (r_reg_get (esil->anal->reg, str, -1)) {
		return R_ANAL_ESIL_PARM_REG;
	}
	return R_ANAL_ESIL_PARM_INVALID;
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
	case R_ANAL_ESIL_PARM_NUM:
		*num = r_num_get (NULL, str);
		if (size) {
			*size = esil->anal->bits;
		}
		return true;
	case R_ANAL_ESIL_PARM_REG:
		if (!r_anal_esil_reg_read (esil, str, num, size)) {
			break;
		}
		return true;
	default:
		if (esil->verbose) {
			eprintf ("Invalid arg (%s)\n", str);
		}
		esil->parse_stop = 1;
		break;
	}
	return false;
}

R_API int r_anal_esil_get_parm(RAnalEsil *esil, const char *str, ut64 *num) {
	return r_anal_esil_get_parm_size (esil, str, num, NULL);
}

R_API bool r_anal_esil_reg_write(RAnalEsil *esil, const char *dst, ut64 num) {
	bool ret = 0;
	IFDBG { eprintf ("%s=0x%" PFMT64x "\n", dst, num); }
	if (esil && esil->cb.hook_reg_write) {
		ret = esil->cb.hook_reg_write (esil, dst, &num);
	}
	if (!ret && esil && esil->cb.reg_write) {
		ret = esil->cb.reg_write (esil, dst, num);
	}
	return ret;
}

R_API bool r_anal_esil_reg_read_nocallback(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	void *old_hook_reg_read = (void *) esil->cb.hook_reg_read;
	esil->cb.hook_reg_read = NULL;
	bool ret = r_anal_esil_reg_read (esil, regname, num, size);
	esil->cb.hook_reg_read = old_hook_reg_read;
	return ret;
}

R_API bool r_anal_esil_reg_read(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	r_return_val_if_fail (esil && regname && num, false);
	bool ret = false;
	ut64 localnum; // XXX why is this necessary?
	if (!esil || !regname) {
		return false;
	}
	if (!num) {
		num = &localnum;
	}
	*num = 0LL;
	if (size) {
		*size = esil->anal->bits;
	}
	if (esil->cb.hook_reg_read) {
		ret = esil->cb.hook_reg_read (esil, regname, num, size);
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read (esil, regname, num, size);
	}
	return ret;
}

R_API bool r_anal_esil_signext(RAnalEsil *esil, bool assign) {
	bool ret = false;
	ut64 src, dst;

	char *p_src = r_anal_esil_pop (esil);
	if (!p_src) {
		return false;
	}

	if (!r_anal_esil_get_parm (esil, p_src, &src)) {
		ERR ("esil_of: empty stack");
		free (p_src);
		return false;
	}

	char *p_dst = r_anal_esil_pop (esil);
	if (!p_dst) {
		free (p_src);
		return false;
	}

	if (!r_anal_esil_get_parm (esil, p_dst, &dst)) {
		ERR ("esil_of: empty stack");
		free (p_src);
		free (p_dst);
		return false;
	} else {
		free (p_dst);
	}
	
	//Make sure the other bits are 0
	src &= UT64_MAX >> (64 - dst); 

	ut64 m = 0;
	if (dst < 64) {
		m = 1ULL << (dst - 1);
	}

	// dst = (dst & ((1U << src_bit) - 1)); // clear upper bits
	if (assign) {
		ret = r_anal_esil_reg_write (esil, p_src, ((src ^ m) - m));
	} else {
		ret = r_anal_esil_pushnum (esil, ((src ^ m) - m));
	}

	free (p_src);
	return ret;
}

// sign extension operator for use in idiv, imul, movsx*
// and other instructions involving signed values, extends n bit value to 64 bit value
// example : >"ae 8,0x81,~" ( <src bit width>,<value>,~ )
// output  : 0xffffffffffffff81
static bool esil_signext(RAnalEsil *esil) {
	return r_anal_esil_signext(esil, false);
}

// sign extension assignement
// example : > "ae 0x81,a0,="
//           > "ae 8,a0,~="   ( <src bit width>,register,~= )
// output  : > ar a0
//           0xffffff81
static bool esil_signexteq(RAnalEsil *esil) {
	return r_anal_esil_signext(esil, true);
}

static bool esil_zf(RAnalEsil *esil) {
	return r_anal_esil_pushnum (esil, !(esil->cur & genmask (esil->lastsz - 1)));
}

// checks if there was a carry from bit x (x,$c)
static bool esil_cf(RAnalEsil *esil) {
	char *src = r_anal_esil_pop (esil);

	if (!src) {
		return false;
	}

	if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_NUM) {
		//I'd wish we could enforce consts here
		//I can't say why, but I feel like "al,$c" would be cancer af
		//	- condret
		free (src);
		return false;
	}
	ut64 bit;
	r_anal_esil_get_parm (esil, src, &bit);
	free (src);
	//carry from bit <src>
	//range of src goes from 0 to 63
	//
	//implements bit mod 64
	const ut64 mask = genmask (bit & 0x3f);
	return r_anal_esil_pushnum (esil, (esil->cur & mask) < (esil->old & mask));
}

// checks if there was a borrow from bit x (x,$b)
static bool esil_bf(RAnalEsil *esil) {
	char *src = r_anal_esil_pop (esil);

	if (!src) {
		return false;
	}

	if (r_anal_esil_get_parm_type (esil, src) != R_ANAL_ESIL_PARM_NUM) {
		free (src);
		return false;
	}
	ut64 bit;
	r_anal_esil_get_parm (esil, src, &bit);
	free (src);
	//borrow from bit <src>
	//range of src goes from 1 to 64
	//	you cannot borrow from bit 0, bc bit -1 cannot not exist
	//
	//implements (bit - 1) mod 64
	const ut64 mask = genmask ((bit + 0x3f) & 0x3f);
	return r_anal_esil_pushnum (esil, (esil->old & mask) < (esil->cur & mask));
}

static bool esil_pf(RAnalEsil *esil) {
	// Set if the number of set bits in the least significant _byte_ is a multiple of 2.
	//   - Taken from: https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits
	const ut64 c1 = 0x0101010101010101ULL;
	const ut64 c2 = 0x8040201008040201ULL;
	const ut64 c3 = 0x1FF;
	// Take only the least significant byte.
	ut64 lsb = esil->cur & 0xff;
	return r_anal_esil_pushnum (esil, !((((lsb * c1) & c2) % c3) & 1));
}

// like carry
// checks overflow from bit x (x,$o)
//	x,$o ===> x,$c,x-1,$c,^
static bool esil_of(RAnalEsil *esil) {
	char *p_bit = r_anal_esil_pop (esil);

	if (!p_bit) {
		return false;
	}

	if (r_anal_esil_get_parm_type (esil, p_bit) != R_ANAL_ESIL_PARM_NUM) {
		free (p_bit);
		return false;
	}
	ut64 bit;

	if (!r_anal_esil_get_parm (esil, p_bit, &bit)) {
		ERR ("esil_of: empty stack");
		free (p_bit);
		return false;
	}
	free (p_bit);

	const ut64 m[2] = {genmask (bit & 0x3f), genmask ((bit + 0x3f) & 0x3f)};
	const ut64 result = ((esil->cur & m[0]) < (esil->old & m[0])) ^ ((esil->cur & m[1]) < (esil->old & m[1]));
	ut64 res = r_anal_esil_pushnum (esil, result);
	return res;
}

//checks sign bit at x (x,$s)
static bool esil_sf(RAnalEsil *esil) {
	r_return_val_if_fail (esil, false);

	char *p_size = r_anal_esil_pop (esil);
	r_return_val_if_fail (p_size, false);

	if (r_anal_esil_get_parm_type (esil, p_size) != R_ANAL_ESIL_PARM_NUM) {
		free (p_size);
		return false;
	}
	ut64 size, num;
	r_anal_esil_get_parm (esil, p_size, &size);
	free (p_size);

	if (size > 63) {
		num = 0;
	} else {
		num = (esil->cur >> size) & 1;
	}
	ut64 res = r_anal_esil_pushnum (esil, num);
	return res;
}

static bool esil_ds(RAnalEsil *esil) {
	r_return_val_if_fail (esil, false);
	return r_anal_esil_pushnum (esil, esil->delay);
}

static bool esil_jt(RAnalEsil *esil) {
	r_return_val_if_fail (esil, false);
	return r_anal_esil_pushnum (esil, esil->jump_target);
}

static bool esil_js(RAnalEsil *esil) {
	r_return_val_if_fail (esil, false);
	return r_anal_esil_pushnum (esil, esil->jump_target_set);
}

//regsize
//can we please deprecate this, it's neither accurate, nor needed
//plugins should know regsize, and since this is a const even users should know this: ?´e anal.bits´/8
//	- condret
// YES PLS KILL IT
static bool esil_rs(RAnalEsil *esil) {
	r_return_val_if_fail (esil && esil->anal, false);
	return r_anal_esil_pushnum (esil, esil->anal->bits >> 3);
}

//can we please deprecate this, plugins should know their current address
//even if they don't know it, $$ should be equal to PC register at the begin of each expression
//	- condret
// YES PLS KILL IT
static bool esil_address(RAnalEsil *esil) {
	r_return_val_if_fail (esil, false);
	return r_anal_esil_pushnum (esil, esil->address);
}

static bool esil_weak_eq(RAnalEsil *esil) {
	r_return_val_if_fail (esil && esil->anal, false);
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);

	if (!(dst && src && (r_anal_esil_get_parm_type(esil, dst) == R_ANAL_ESIL_PARM_REG))) {
		free (dst);
		free (src);
		return false;
	}

	ut64 src_num;
	if (r_anal_esil_get_parm (esil, src, &src_num)) {
		(void)r_anal_esil_reg_write (esil, dst, src_num);
		free (src);
		free (dst);
		return true;
	}

	free (src);
	free (dst);
	return false;
}

static bool esil_eq(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (!src || !dst) {
		if (esil->verbose) {
			eprintf ("Missing elements in the esil stack for '=' at 0x%08"PFMT64x"\n", esil->address);
		}
		free (src);
		free (dst);
		return false;
	}
	if (ispackedreg (esil, dst)) {
		char *src2 = r_anal_esil_pop (esil);
		char *newreg = r_str_newf ("%sl", dst);
		if (r_anal_esil_get_parm (esil, src2, &num2)) {
			ret = r_anal_esil_reg_write (esil, newreg, num2);
		}
		free (newreg);
		free (src2);
		goto beach;
	}

	if (src && dst && r_anal_esil_reg_read_nocallback (esil, dst, &num, NULL)) {
		if (r_anal_esil_get_parm (esil, src, &num2)) {
			ret = r_anal_esil_reg_write (esil, dst, num2);
			esil->cur = num2;
			esil->old = num;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
		} else {
			ERR ("esil_eq: invalid src");
		}
	} else {
		ERR ("esil_eq: invalid parameters");
	}
beach:
	free (src);
	free (dst);
	return ret;
}

static bool esil_neg(RAnalEsil *esil) {
	bool ret = false;
	char *src = r_anal_esil_pop (esil);
	if (src) {
		ut64 num;
		if (r_anal_esil_get_parm (esil, src, &num)) {
			r_anal_esil_pushnum (esil, !num);
			ret = true;
		} else {
			if (isregornum (esil, src, &num)) {
				ret = true;
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

static bool esil_negeq(RAnalEsil *esil) {
	bool ret = false;
	ut64 num;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_reg_read (esil, src, &num, NULL)) {
		num = !num;
		r_anal_esil_reg_write (esil, src, num);
		ret = true;
	} else {
		ERR ("esil_negeq: empty stack");
	}
	free (src);
	//r_anal_esil_pushnum (esil, ret);
	return ret;
}

static bool esil_nop(RAnalEsil *esil) {
	return true;
}

static bool esil_andeq(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num & num2;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			r_anal_esil_reg_write (esil, dst, num & num2);
			ret = true;
		} else {
			ERR ("esil_andeq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_oreq(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num | num2;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_anal_esil_reg_write (esil, dst, num | num2);
		} else {
			ERR ("esil_ordeq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_xoreq(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
				esil->old = num;
				esil->cur = num ^ num2;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_anal_esil_reg_write (esil, dst, num ^ num2);
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

static bool esil_trap(RAnalEsil *esil) {
	ut64 s, d;
	if (popRN (esil, &s) && popRN (esil, &d)) {
		esil->trap = s;
		esil->trap_code = d;
		return r_anal_esil_fire_trap (esil, (int)s, (int)d);
	}
	ERR ("esil_trap: missing parameters in stack");
	return false;
}

static bool esil_bits(RAnalEsil *esil) {
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

static bool esil_interrupt(RAnalEsil *esil) {
	ut64 interrupt;
	if (popRN (esil, &interrupt)) {
		return r_anal_esil_fire_interrupt (esil, (ut32)interrupt);
	}
	return false;
}

static bool esil_syscall(RAnalEsil *esil) {
	ut64 sc;
	if (popRN (esil, &sc)) {
		return r_anal_esil_do_syscall (esil, (ut32)sc);
	}
	return false;
}

// This function also sets internal vars which is used in flag calculations.
static bool esil_cmp(RAnalEsil *esil) {
	ut64 num, num2;
	bool ret = false;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
			if (r_reg_get (esil->anal->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			} else if (r_reg_get (esil->anal->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg (esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
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

static bool esil_if(RAnalEsil *esil) {
	ut64 num = 0LL;
	if (esil->skip) {
		esil->skip++;
		return true;
	}
	bool ret = false;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		// condition not matching, skipping until
		if (!num) {
			esil->skip++;
		}
		ret = true;
	}
	free (src);
	return ret;
}

static bool esil_lsl(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (num2 > sizeof (ut64) * 8) {
				ERR ("esil_lsl: shift is too big");
			} else {
				if (num2 > 63) {
					r_anal_esil_pushnum (esil, 0);
				} else {
					r_anal_esil_pushnum (esil, num << num2);
				}
				ret = true;
			}
		} else {
			ERR ("esil_lsl: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_lsleq(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (num2 > sizeof (ut64) * 8) {
				ERR ("esil_lsleq: shift is too big");
			} else {
				esil->old = num;
				if (num2 > 63) {
					num = 0;
				} else {
					num <<= num2;
				}
				esil->cur = num;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				r_anal_esil_reg_write (esil, dst, num);
				ret = true;
			}
		} else {
			ERR ("esil_lsleq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_lsr(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 res = num >> R_MIN (num2, 63);
			r_anal_esil_pushnum (esil, res);
			ret = true;
		} else {
			ERR ("esil_lsr: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_lsreq(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_reg_read (esil, dst, &num, NULL)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			if (num2 > 63) {
				if (esil->verbose) {
					eprintf ("Invalid shift at 0x%08"PFMT64x"\n", esil->address);
				}
				num2 = 63;
			}
			esil->old = num;
			num >>= num2;
			esil->cur = num;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			r_anal_esil_reg_write (esil, dst, num);
			ret = true;
		} else {
			ERR ("esil_lsreq: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_asreq(RAnalEsil *esil) {
	bool ret = false;
	int regsize = 0;
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
							eprintf ("Invalid asreq shift of %d at 0x%"PFMT64x"\n", shift, esil->address);
						}
						shift = 0;
					}
					if (param_num > regsize - 1) {
						// capstone bug?
						if (esil->verbose) {
							eprintf ("Invalid asreq shift of %"PFMT64d" at 0x%"PFMT64x"\n", param_num, esil->address);
						}
						param_num = 30;
					}
					if (shift >= 63) {
						// LL can't handle LShift of 63 or more
						if (esil->verbose) {
							eprintf ("Invalid asreq shift of %d at 0x%08"PFMT64x"\n", shift, esil->address);
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
			r_anal_esil_reg_write (esil, op, res);
			// r_anal_esil_pushnum (esil, res);
			ret = true;
		} else {
			if (esil->verbose) {
				eprintf ("esil_asr: empty stack");
			}
		}
	}
	free (param);
	free (op);
	return ret;
}

static bool esil_asr(RAnalEsil *esil) {
	bool ret = false;
	int regsize = 0;
	ut64 op_num = 0, param_num = 0;
	char *op = r_anal_esil_pop (esil);
	char *param = r_anal_esil_pop (esil);
	if (op && r_anal_esil_get_parm_size (esil, op, &op_num, &regsize)) {
		if (param && r_anal_esil_get_parm (esil, param, &param_num)) {
			if (param_num > regsize - 1) {
				// capstone bug?
				if (esil->verbose) {
					eprintf ("Invalid asr shift of %"PFMT64d" at 0x%"PFMT64x"\n", param_num, esil->address);
				}
				param_num = 30;
			}
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
				if (op_num & (1ULL << (regsize - 1))) {
					left_bits = (1ULL << param_num) - 1;
					left_bits <<= regsize - param_num;
				}
				op_num = left_bits | (op_num >> param_num);
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			r_anal_esil_pushnum (esil, res);
			ret = true;
		} else {
			ERR ("esil_asr: empty stack");
		}
	}
	free (param);
	free (op);
	return ret;
}

static bool esil_ror(RAnalEsil *esil) {
	bool ret = 0;
	int regsize;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num >> num2) | (num << ((-(st64)num2) & mask));
			r_anal_esil_pushnum (esil, res);
			ret = true;
		} else {
			ERR ("esil_ror: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_rol(RAnalEsil *esil) {
	bool ret = 0;
	int regsize;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm_size (esil, dst, &num, &regsize)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num << num2) | (num >> ((-(st64)num2) & mask));
			r_anal_esil_pushnum (esil, res);
			ret = true;
		} else {
			ERR ("esil_rol: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_and(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num &= num2;
			r_anal_esil_pushnum (esil, num);
			ret = true;
		} else {
			ERR ("esil_and: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_xor(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num ^= num2;
			r_anal_esil_pushnum (esil, num);
			ret = true;
		} else {
			ERR ("esil_xor: empty stack");
		}
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_or(RAnalEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			num |= num2;
			r_anal_esil_pushnum (esil, num);
			ret = true;
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
	case R_ANAL_TRAP_INVALID:
		return "invalid";
	case R_ANAL_TRAP_UNALIGNED:
		return "unaligned";
	case R_ANAL_TRAP_TODO:
		return "todo";
	default:
		return "unknown";
	}
}

R_API bool r_anal_esil_dumpstack(RAnalEsil *esil) {
	r_return_val_if_fail (esil, false);
	int i;
	if (esil->trap) {
		eprintf ("ESIL TRAP type %d code 0x%08x %s\n",
			esil->trap, esil->trap_code,
			r_anal_esil_trapstr (esil->trap));
	}
	if (esil->stackptr < 1) {
		return false;
	}
	for (i = esil->stackptr - 1; i >= 0; i--) {
		esil->anal->cb_printf ("%s\n", esil->stack[i]);
	}
	return true;
}

static bool esil_break(RAnalEsil *esil) {
	esil->parse_stop = 1;
	return 1;
}

static bool esil_clear(RAnalEsil *esil) {
	char *r;
	while ((r = r_anal_esil_pop (esil))) {
		free (r);
	}
	return 1;
}

static bool esil_todo(RAnalEsil *esil) {
	esil->parse_stop = 2;
	return 1;
}

static bool esil_goto(RAnalEsil *esil) {
	ut64 num = 0;
	char *src = r_anal_esil_pop (esil);
	if (src && *src && r_anal_esil_get_parm (esil, src, &num)) {
		esil->parse_goto = num;
	}
	free (src);
	return 1;
}

static bool esil_repeat(RAnalEsil *esil) {
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

static bool esil_pop(RAnalEsil *esil) {
	char *dst = r_anal_esil_pop (esil);
	free (dst);
	return 1;
}

static bool esil_mod(RAnalEsil *esil) {
	bool ret = false;
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
			ret = true;
		}
	} else {
		ERR ("esil_mod: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_signed_mod(RAnalEsil *esil) {
	bool ret = false;
	st64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, (ut64 *)&s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, (ut64 *)&d)) {
			if (ST64_DIV_OVFCHK (d, s)) {
				if (esil->verbose > 0) {
					eprintf ("0x%08"PFMT64x" esil_mod: Division by zero!\n", esil->address);
				}
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_anal_esil_pushnum (esil, d % s);
			}
			ret = true;
		}
	} else {
		ERR ("esil_mod: invalid parameters");
	}
	free (dst);
	free (src);
	return ret;
}

static bool esil_modeq(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				esil->old = d;
				esil->cur = d % s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				r_anal_esil_reg_write (esil, dst, d % s);
			} else {
				ERR ("esil_modeq: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = true;
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

static bool esil_div(RAnalEsil *esil) {
	bool ret = false;
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
			ret = true;
		}
	} else {
		ERR ("esil_div: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_signed_div(RAnalEsil *esil) {
	bool ret = false;
	st64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, (ut64 *)&s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, (ut64 *)&d)) {
			if (ST64_DIV_OVFCHK (d, s)) {
				ERR ("esil_div: Division by zero!");
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				r_anal_esil_pushnum (esil, d / s);
			}
			ret = true;
		}
	} else {
		ERR ("esil_div: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_diveq(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			if (s) {
				esil->old = d;
				esil->cur = d / s;
				esil->lastsz = esil_internal_sizeof_reg (esil, dst);
				r_anal_esil_reg_write (esil, dst, d / s);
			} else {
				// eprintf ("0x%08"PFMT64x" esil_diveq: Division by zero!\n", esil->address);
				esil->trap = R_ANAL_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = true;
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

static bool esil_long_mul(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d; 
	ut64 hi, lo;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			mult64to128(s, d, &hi, &lo);
			r_anal_esil_pushnum (esil, hi);
			r_anal_esil_pushnum (esil, lo);
			ret = true;
		} else {
			ERR ("esil_long_mul: empty stack");
		}
	} else {
		ERR ("esil_long_mul: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_mul(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &d)) {
			r_anal_esil_pushnum (esil, d * s);
			ret = true;
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

static bool esil_muleq(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d * s;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_anal_esil_reg_write (esil, dst, s * d);
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

static bool esil_add(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if ((src && r_anal_esil_get_parm (esil, src, &s)) && (dst && r_anal_esil_get_parm (esil, dst, &d))) {
		r_anal_esil_pushnum (esil, s + d);
		ret = true;
	} else {
		ERR ("esil_add: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_addeq(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d + s;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_anal_esil_reg_write (esil, dst, s + d);
		}
	} else {
		ERR ("esil_addeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_inc(RAnalEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s++;
		ret = r_anal_esil_pushnum (esil, s);
	} else {
		ERR ("esil_inc: invalid parameters");
	}
	free (src);
	return ret;
}

static bool esil_inceq(RAnalEsil *esil) {
	bool ret = false;
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

static bool esil_sub(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if ((src && r_anal_esil_get_parm (esil, src, &s)) && (dst && r_anal_esil_get_parm (esil, dst, &d))) {
		ret = r_anal_esil_pushnum (esil, d - s);
	} else {
		ERR ("esil_sub: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_subeq(RAnalEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		if (dst && r_anal_esil_reg_read (esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d - s;
			esil->lastsz = esil_internal_sizeof_reg (esil, dst);
			ret = r_anal_esil_reg_write (esil, dst, d - s);
		}
	} else {
		ERR ("esil_subeq: invalid parameters");
	}
	free (src);
	free (dst);
	return ret;
}

static bool esil_dec(RAnalEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		s--;
		ret = r_anal_esil_pushnum (esil, s);
	} else {
		ERR ("esil_dec: invalid parameters");
	}
	free (src);
	return ret;
}

static bool esil_deceq(RAnalEsil *esil) {
	bool ret = false;
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
static bool esil_poke_n(RAnalEsil *esil, int bits) {
	ut64 bitmask = genmask (bits - 1);
	ut64 num, num2, addr;
	ut8 b[8] = {0};
	ut64 n;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	int bytes = R_MIN (sizeof (b), bits / 8);
	if (bits % 8) {
		free (src);
		free (dst);
		return false;
	}
	bool ret = false;
	//eprintf ("GONA POKE %d src:%s dst:%s\n", bits, src, dst);
	char *src2 = NULL;
	if (src && r_anal_esil_get_parm (esil, src, &num)) {
		if (dst && r_anal_esil_get_parm (esil, dst, &addr)) {
			if (bits == 128) {
				src2 = r_anal_esil_pop (esil);
				if (src2 && r_anal_esil_get_parm (esil, src2, &num2)) {
					r_write_ble (b, num, esil->anal->big_endian, 64);
					ret = r_anal_esil_mem_write (esil, addr, b, bytes);
					if (ret == 0) {
						r_write_ble (b, num2, esil->anal->big_endian, 64);
						ret = r_anal_esil_mem_write (esil, addr + 8, b, bytes);
					}
					goto out;
				}
				ret = 0;
				goto out;
			}
			// this is a internal peek performed before a poke
			// we disable hooks to avoid run hooks on internal peeks
			void * oldhook = (void*)esil->cb.hook_mem_read;
			esil->cb.hook_mem_read = NULL;
			r_anal_esil_mem_read (esil, addr, b, bytes);
			esil->cb.hook_mem_read = oldhook;
			n = r_read_ble64 (b, esil->anal->big_endian);
			esil->old = n;
			esil->cur = num;
			esil->lastsz = bits;
			num = num & bitmask;
			r_write_ble (b, num, esil->anal->big_endian, bits);
			ret = r_anal_esil_mem_write (esil, addr, b, bytes);
		}
	}
out:
	free (src2);
	free (src);
	free (dst);
	return ret;
}

static bool esil_poke1(RAnalEsil *esil) {
	return esil_poke_n (esil, 8);
}

static bool esil_poke2(RAnalEsil *esil) {
	return esil_poke_n (esil, 16);
}

static bool esil_poke3(RAnalEsil *esil) {
	return esil_poke_n (esil, 24);
}

static bool esil_poke4(RAnalEsil *esil) {
	return esil_poke_n (esil, 32);
}

static bool esil_poke8(RAnalEsil *esil) {
	return esil_poke_n (esil, 64);
}

static bool esil_poke16(RAnalEsil *esil) {
	return esil_poke_n (esil, 128);
}

static bool esil_poke(RAnalEsil *esil) {
	return esil_poke_n (esil, esil->anal->bits);
}

static bool esil_poke_some(RAnalEsil *esil) {
	bool ret = false;
	int i, regsize;
	ut64 ptr, regs = 0, tmp;
	char *count, *dst = r_anal_esil_pop (esil);

	if (dst && r_anal_esil_get_parm_size (esil, dst, &tmp, &regsize)) {
		// reg
		isregornum (esil, dst, &ptr);
		count = r_anal_esil_pop (esil);
		if (count) {
			isregornum (esil, count, &regs);
			if (regs > 0) {
				ut8 b[8] = {0};
				ut64 num64;
				for (i = 0; i < regs; i++) {
					char *foo = r_anal_esil_pop (esil);
					if (!foo) {
						// avoid looping out of stack
						free (dst);
						free (count);
						return true;
					}
					r_anal_esil_get_parm_size (esil, foo, &tmp, &regsize);
					isregornum (esil, foo, &num64);
					r_write_ble (b, num64, esil->anal->big_endian, regsize);
					const int size_bytes = regsize / 8;
					const ut32 written = r_anal_esil_mem_write (esil, ptr, b, size_bytes);
					if (written != size_bytes) {
						//eprintf ("Cannot write at 0x%08" PFMT64x "\n", ptr);
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

static bool esil_peek_n(RAnalEsil *esil, int bits) {
	if (bits & 7) {
		return false;
	}
	bool ret = false;
	char res[32];
	ut64 addr;
	ut32 bytes = bits / 8;
	char *dst = r_anal_esil_pop (esil);
	if (!dst) {
		eprintf ("ESIL-ERROR at 0x%08"PFMT64x": Cannot peek memory without specifying an address\n", esil->address);
		return false;
	}
	//eprintf ("GONA PEEK %d dst:%s\n", bits, dst);
	if (dst && isregornum (esil, dst, &addr)) {
		if (bits == 128) {
			ut8 a[sizeof (ut64) * 2] = {0};
			ret = r_anal_esil_mem_read (esil, addr, a, bytes);
			ut64 b = r_read_ble64 (&a, 0); //esil->anal->big_endian);
			ut64 c = r_read_ble64 (&a[8], 0); //esil->anal->big_endian);
			snprintf (res, sizeof (res), "0x%" PFMT64x, b);
			r_anal_esil_push (esil, res);
			snprintf (res, sizeof (res), "0x%" PFMT64x, c);
			r_anal_esil_push (esil, res);
			free (dst);
			return ret;
		}
		ut64 bitmask = genmask (bits - 1);
		ut8 a[sizeof(ut64)] = {0};
		ret = !!r_anal_esil_mem_read (esil, addr, a, bytes);
#if 0
		ut64 b = r_read_ble64 (a, esil->anal->big_endian);
#else
		ut64 b = r_read_ble64 (a, 0);
		if (esil->anal->big_endian) {
			r_mem_swapendian ((ut8*)&b, (const ut8*)&b, bytes);
		}
#endif
		snprintf (res, sizeof (res), "0x%" PFMT64x, b & bitmask);
		r_anal_esil_push (esil, res);
		esil->lastsz = bits;
	}
	free (dst);
	return ret;
}

static bool esil_peek1(RAnalEsil *esil) {
	return esil_peek_n (esil, 8);
}

static bool esil_peek2(RAnalEsil *esil) {
	return esil_peek_n (esil, 16);
}

static bool esil_peek3(RAnalEsil *esil) {
	return esil_peek_n (esil, 24);
}

static bool esil_peek4(RAnalEsil *esil) {
	return esil_peek_n (esil, 32);
}

static bool esil_peek8(RAnalEsil *esil) {
	return esil_peek_n (esil, 64);
}

static bool esil_peek16(RAnalEsil *esil) {
	// packed only
	return esil_peek_n (esil, 128);
}

static bool esil_peek(RAnalEsil *esil) {
	return esil_peek_n (esil, esil->anal->bits);
};

static bool esil_peek_some(RAnalEsil *esil) {
	int i;
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
				ut8 a[4];
				for (i = 0; i < regs; i++) {
					char *foo = r_anal_esil_pop (esil);
					if (!foo) {
						ERR ("Cannot pop in peek");
						free (dst);
						free (count);
						return false;
					}
					bool oks = r_anal_esil_mem_read (esil, ptr, a, 4);
					if (!oks) {
						if (esil->verbose) {
							eprintf ("Cannot peek from 0x%08" PFMT64x "\n", ptr);
						}
						free (dst);
						free (count);
						return false;
					}
					ut32 num32 = r_read_ble32 (a, esil->anal->big_endian);
					r_anal_esil_reg_write (esil, foo, num32);
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

static bool esil_mem_oreq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_oreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_oreq1(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 8);
}
static bool esil_mem_oreq2(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 16);
}
static bool esil_mem_oreq4(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 32);
}
static bool esil_mem_oreq8(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, 64);
}
static bool esil_mem_oreq(RAnalEsil *esil) {
	return esil_mem_oreq_n (esil, esil->anal->bits);
}

/* XOREQ */

static bool esil_mem_xoreq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_xoreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_xoreq1(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 8);
}
static bool esil_mem_xoreq2(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 16);
}
static bool esil_mem_xoreq4(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 32);
}
static bool esil_mem_xoreq8(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, 64);
}
static bool esil_mem_xoreq(RAnalEsil *esil) {
	return esil_mem_xoreq_n (esil, esil->anal->bits);
}

/* ANDEQ */

static bool esil_mem_andeq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_andeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_andeq1(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 8);
}
static bool esil_mem_andeq2(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 16);
}
static bool esil_mem_andeq4(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 32);
}
static bool esil_mem_andeq8(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, 64);
}
static bool esil_mem_andeq(RAnalEsil *esil) {
	return esil_mem_andeq_n (esil, esil->anal->bits);
}

/* ADDEQ */

static bool esil_mem_addeq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_addeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_addeq1(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 8);
}
static bool esil_mem_addeq2(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 16);
}
static bool esil_mem_addeq4(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 32);
}
static bool esil_mem_addeq8(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, 64);
}
static bool esil_mem_addeq(RAnalEsil *esil) {
	return esil_mem_addeq_n (esil, esil->anal->bits);
}

/* SUBEQ */

static bool esil_mem_subeq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_subeq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_subeq1(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 8);
}
static bool esil_mem_subeq2(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 16);
}
static bool esil_mem_subeq4(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 32);
}
static bool esil_mem_subeq8(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, 64);
}
static bool esil_mem_subeq(RAnalEsil *esil) {
	return esil_mem_subeq_n (esil, esil->anal->bits);
}

/* MODEQ */

static bool esil_mem_modeq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
				ret = false;
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

static bool esil_mem_modeq1(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 8);
}
static bool esil_mem_modeq2(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 16);
}
static bool esil_mem_modeq4(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 32);
}
static bool esil_mem_modeq8(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, 64);
}
static bool esil_mem_modeq(RAnalEsil *esil) {
	return esil_mem_modeq_n (esil, esil->anal->bits);
}

/* DIVEQ */

static bool esil_mem_diveq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		ERR ("esil_mem_diveq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_diveq1(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 8);
}
static bool esil_mem_diveq2(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 16);
}
static bool esil_mem_diveq4(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 32);
}
static bool esil_mem_diveq8(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, 64);
}
static bool esil_mem_diveq(RAnalEsil *esil) {
	return esil_mem_diveq_n (esil, esil->anal->bits);
}

/* MULEQ */

static bool esil_mem_muleq_n(RAnalEsil *esil, int bits, ut64 bitmask) {
	bool ret = false;
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
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_muleq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_muleq1(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 8, UT8_MAX);
}
static bool esil_mem_muleq2(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 16, UT16_MAX);
}
static bool esil_mem_muleq4(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 32, UT32_MAX);
}
static bool esil_mem_muleq8(RAnalEsil *esil) {
	return esil_mem_muleq_n (esil, 64, UT64_MAX);
}

static bool esil_mem_muleq(RAnalEsil *esil) {
	switch (esil->anal->bits) {
	case 64: return esil_mem_muleq8 (esil);
	case 32: return esil_mem_muleq4 (esil);
	case 16: return esil_mem_muleq2 (esil);
	case 8: return esil_mem_muleq1 (esil);
	}
	return 0;
}

/* INCEQ */

static bool esil_mem_inceq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
	ut64 s;
	char *off = r_anal_esil_pop (esil);
	char *src = NULL;
	if (off) {
		r_anal_esil_push (esil, off);
		ret = (!!esil_peek_n (esil, bits));
		src = r_anal_esil_pop (esil);
		if (src && r_anal_esil_get_parm (esil, src, &s)) {
			esil->old = s;
			s++;
			esil->cur = s;
			esil->lastsz = bits;
			r_anal_esil_pushnum (esil, s);
			r_anal_esil_push (esil, off);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_inceq_n: invalid parameters");
	}
	free (src);
	free (off);
	return ret;
}

static bool esil_mem_inceq1(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 8);
}
static bool esil_mem_inceq2(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 16);
}
static bool esil_mem_inceq4(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 32);
}
static bool esil_mem_inceq8(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, 64);
}
static bool esil_mem_inceq(RAnalEsil *esil) {
	return esil_mem_inceq_n (esil, esil->anal->bits);
}

/* DECEQ */

static bool esil_mem_deceq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
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
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_deceq_n: invalid parameters");
	}
	free (src);
	free (off);
	return ret;
}

static bool esil_mem_deceq1(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 8);
}
static bool esil_mem_deceq2(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 16);
}
static bool esil_mem_deceq4(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 32);
}
static bool esil_mem_deceq8(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, 64);
}
static bool esil_mem_deceq(RAnalEsil *esil) {
	return esil_mem_deceq_n (esil, esil->anal->bits);
}

/* LSLEQ */

static bool esil_mem_lsleq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		if (s > sizeof (ut64) * 8) {
			ERR ("esil_mem_lsleq_n: shift is too big");
		} else {
			r_anal_esil_push (esil, dst);
			ret = (!!esil_peek_n (esil, bits));
			src1 = r_anal_esil_pop (esil);
			if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
				if (s > 63) {
					d = 0;
				} else {
					d <<= s;
				}
				r_anal_esil_pushnum (esil, d);
				r_anal_esil_push (esil, dst);
				ret &= (!!esil_poke_n (esil, bits));
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		ERR ("esil_mem_lsleq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_lsleq1(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 8);
}
static bool esil_mem_lsleq2(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 16);
}
static bool esil_mem_lsleq4(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 32);
}
static bool esil_mem_lsleq8(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, 64);
}
static bool esil_mem_lsleq(RAnalEsil *esil) {
	return esil_mem_lsleq_n (esil, esil->anal->bits);
}

/* LSREQ */

static bool esil_mem_lsreq_n(RAnalEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = r_anal_esil_pop (esil);
	char *src0 = r_anal_esil_pop (esil);
	char *src1 = NULL;
	if (src0 && r_anal_esil_get_parm (esil, src0, &s)) {
		r_anal_esil_push (esil, dst);
		ret = (!!esil_peek_n (esil, bits));
		src1 = r_anal_esil_pop (esil);
		if (src1 && r_anal_esil_get_parm (esil, src1, &d)) {
			d >>= s;
			r_anal_esil_pushnum (esil, d);
			r_anal_esil_push (esil, dst);
			ret &= (!!esil_poke_n (esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ERR ("esil_mem_lsreq_n: invalid parameters");
	}
	free (dst);
	free (src0);
	free (src1);
	return ret;
}

static bool esil_mem_lsreq1(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 8);
}
static bool esil_mem_lsreq2(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 16);
}
static bool esil_mem_lsreq4(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 32);
}
static bool esil_mem_lsreq8(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, 64);
}
static bool esil_mem_lsreq(RAnalEsil *esil) {
	return esil_mem_lsreq_n (esil, esil->anal->bits);
}

/* get value of register or memory reference and push the value */
static bool esil_num(RAnalEsil *esil) {
	char *dup_me;
	ut64 dup;
	if (!esil) {
		return false;
	}
	if (!(dup_me = r_anal_esil_pop (esil))) {
		return false;
	}
	if (!r_anal_esil_get_parm (esil, dup_me, &dup)) {
		free (dup_me);
		return false;
	}
	free (dup_me);
	return r_anal_esil_pushnum (esil, dup);
}

/* duplicate the last element in the stack */
static bool esil_dup(RAnalEsil *esil) {
	if (!esil || !esil->stack || esil->stackptr < 1 || esil->stackptr > (esil->stacksize - 1)) {
		return false;
	}
	return r_anal_esil_push (esil, esil->stack[esil->stackptr-1]);
}

static bool esil_swap(RAnalEsil *esil) {
	char *tmp;
	if (!esil || !esil->stack || esil->stackptr < 2) {
		return false;
	}
	if (!esil->stack[esil->stackptr-1] || !esil->stack[esil->stackptr-2]) {
		return false;
	}
	tmp = esil->stack[esil->stackptr-1];
	esil->stack[esil->stackptr-1] = esil->stack[esil->stackptr-2];
	esil->stack[esil->stackptr-2] = tmp;
	return true;
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

static bool esil_smaller(RAnalEsil *esil) { // 'dst < src' => 'src,dst,<'
	ut64 num, num2;
	bool ret = false;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
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

static bool esil_bigger(RAnalEsil *esil) { // 'dst > src' => 'src,dst,>'
	ut64 num, num2;
	bool ret = false;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
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

static bool esil_smaller_equal(RAnalEsil *esil) { // 'dst <= src' => 'src,dst,<='
	ut64 num, num2;
	bool ret = false;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
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

static bool esil_bigger_equal(RAnalEsil *esil) { // 'dst >= src' => 'src,dst,>='
	ut64 num, num2;
	bool ret = false;
	char *dst = r_anal_esil_pop (esil);
	char *src = r_anal_esil_pop (esil);
	if (dst && r_anal_esil_get_parm (esil, dst, &num)) {
		if (src && r_anal_esil_get_parm (esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
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

static bool esil_set_jump_target(RAnalEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		esil->jump_target = s;
		esil->jump_target_set = 1;
		ret = true;
	} else {
		R_FREE (src);
		ERR ("esil_set_jump_target: empty stack");
	}
	free (src);
	return ret;
}

static bool esil_set_jump_target_set(RAnalEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		esil->jump_target_set = s;
		ret = true;
	} else {
		R_FREE (src);
		ERR ("esil_set_jump_target_set: empty stack");
	}
	free (src);
	return ret;
}

static bool esil_set_delay_slot(RAnalEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = r_anal_esil_pop (esil);
	if (src && r_anal_esil_get_parm (esil, src, &s)) {
		esil->delay = s;
		ret = true;
	} else {
		R_FREE (src);
		ERR ("esil_set_delay_slot: empty stack");
	}
	free (src);
	return ret;
}

static int esil_get_parm_float(RAnalEsil *esil, const char *str, double *num) {
	return r_anal_esil_get_parm(esil, str, (ut64 *)num);
}

static bool esil_pushnum_float(RAnalEsil *esil, double num) {
	RNumFloat n;
	n.f64 = num;
	return r_anal_esil_pushnum(esil, n.u64);
}

static bool esil_is_nan(RAnalEsil *esil) {
	bool ret = false;
	double s;
	char *src = r_anal_esil_pop(esil);
	if (src) {
		if (esil_get_parm_float(esil, src, &s)) {
			ret = r_anal_esil_pushnum(esil, isnan(s));
		} else {
			ERR("esil_is_nan: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_is_nan: fail to get argument from stack.");
	}
	return ret;
}

static bool esil_int_to_double(RAnalEsil *esil, int sign) {
	bool ret = false;
	RNumFloat s;
	char *src = r_anal_esil_pop(esil);
	if (src) {
		if (r_anal_esil_get_parm(esil, src, &s.u64)) {
			if (sign) {
				ret = esil_pushnum_float(esil, (double)(s.s64) * 1.0);
			} else {
				ret = esil_pushnum_float(esil, (double)(s.u64) * 1.0);
			}
		} else {
			ERR("esil_int_to_float: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_int_to_float: fail to get argument from stack.");
	}
	return ret;
}

static bool esil_signed_to_double(RAnalEsil *esil) {
	return esil_int_to_double(esil, 1);
}

static bool esil_unsigned_to_double(RAnalEsil *esil) {
	return esil_int_to_double(esil, 0);
}

static bool esil_double_to_int(RAnalEsil *esil) {
	bool ret = false;
	RNumFloat s;
	char *src = r_anal_esil_pop(esil);
	if (src) {
		if (esil_get_parm_float(esil, src, &s.f64)) {
			if (isnan(s.f64) || isinf(s.f64)) {
				ERR("esil_float_to_int: nan or inf detected.");
			}
			ret = r_anal_esil_pushnum(esil, (st64)(s.f64));
		} else {
			ERR("esil_float_to_int: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_float_to_int: fail to get argument from stack.");
	}
	return ret;
}

static bool esil_double_to_float(RAnalEsil *esil) {
	bool ret = false;
	RNumFloat d;
	RNumFloat f;
	ut64 s = 0;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (r_anal_esil_get_parm(esil, src, &s) && esil_get_parm_float(esil, dst, &d.f64)) {
		if (isnan(d.f64) || isinf(d.f64)) {
			ret = r_anal_esil_pushnum(esil, d.u64);
		} else if (s == 32) {
			f.f32 = (float)d.f64;
			ret = r_anal_esil_pushnum(esil, f.u32);
		} else if (s == 64) {
			ret = r_anal_esil_pushnum(esil, d.u64);
		/* TODO handle 80 bit and 128 bit floats */
		} else {
			ret = r_anal_esil_pushnum(esil, d.u64);
		}
	} else {
		ERR("esil_float_to_float: invalid parameters.");
	}

	free(dst);
	free(src);
	return ret;
}

static bool esil_float_to_double(RAnalEsil *esil) {
	bool ret = false;
	RNumFloat d;
	ut64 s = 0;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (r_anal_esil_get_parm(esil, src, &s) && esil_get_parm_float(esil, dst, &d.f64)) {
		if (isnan(d.f64) || isinf(d.f64)) {
			ret = esil_pushnum_float(esil, d.f64);
		} else if (s == 32) {
			ret = esil_pushnum_float(esil, (double)d.f32);
		} else if (s == 64) {
			ret = esil_pushnum_float(esil, d.f64);
		/* TODO handle 80 bit and 128 bit floats */
		} else {
			ret = esil_pushnum_float(esil, d.f64);
		}
	} else {
		ERR("esil_float_to_float: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_cmp(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (src && dst && esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s) || isnan(d)) {
			ret = r_anal_esil_pushnum(esil, 0);
		} else {
			ret = r_anal_esil_pushnum(esil, fabs(s - d) <= DBL_EPSILON);
		}
	} else {
		ERR("esil_float_cmp: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_negcmp(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (src && dst && esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s) || isnan(d)) {
			ret = r_anal_esil_pushnum(esil, 0);
		} else {
			ret = r_anal_esil_pushnum(esil, fabs(s - d) >= DBL_EPSILON);
		}
	} else {
		ERR("esil_float_negcmp: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_less(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s) || isnan(d)) {
			ret = r_anal_esil_pushnum(esil, 0);
		} else {
			ret = r_anal_esil_pushnum(esil, d < s);
		}
	} else {
		ERR("esil_float_less: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_lesseq(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s) || isnan(d)) {
			ret = r_anal_esil_pushnum(esil, 0);
		} else {
			ret = r_anal_esil_pushnum(esil, d <= s);
		}
	} else {
		ERR("esil_float_lesseq: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_add(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s)) {
			ret = esil_pushnum_float(esil, s);
		} else if (isnan(d)) {
			ret = esil_pushnum_float(esil, d);
		} else {
			feclearexcept(FE_OVERFLOW);
			double tmp = s + d;
			(void)(tmp); // suppress unused warning
			int raised = fetestexcept(FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float(esil, NAN);
			} else {
				ret = esil_pushnum_float(esil, s + d);
			}
		}
	} else {
		ERR("esil_float_add: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_sub(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s)) {
			ret = esil_pushnum_float(esil, s);
		} else if (isnan(d)) {
			ret = esil_pushnum_float(esil, d);
		} else {
			feclearexcept(FE_OVERFLOW);
			double tmp = d - s;
			(void)(tmp);
			int raised = fetestexcept(FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float(esil, NAN);
			} else {
				ret = esil_pushnum_float(esil, d - s);
			}
		}
	} else {
		ERR("esil_float_sub: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_mul(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s)) {
			ret = esil_pushnum_float(esil, s);
		} else if (isnan(d)) {
			ret = esil_pushnum_float(esil, d);
		} else {
			feclearexcept(FE_OVERFLOW);
			double tmp = s * d;
			(void)(tmp);
			int raised = fetestexcept(FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float(esil, NAN);
			} else {
				ret = esil_pushnum_float(esil, s * d);
			}
		}
	} else {
		ERR("esil_float_mul: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_div(RAnalEsil *esil) {
	bool ret = false;
	double s, d;
	char *dst = r_anal_esil_pop(esil);
	char *src = r_anal_esil_pop(esil);

	if (esil_get_parm_float(esil, src, &s) && esil_get_parm_float(esil, dst, &d)) {
		if (isnan(s)) {
			ret = esil_pushnum_float(esil, s);
		} else if (isnan(d)) {
			ret = esil_pushnum_float(esil, d);
		} else {
			feclearexcept(FE_OVERFLOW);
			double tmp = d / s;
			(void)(tmp);
			int raised = fetestexcept(FE_OVERFLOW);
			if (raised & FE_OVERFLOW) {
				ret = esil_pushnum_float(esil, NAN);
			} else {
				ret = esil_pushnum_float(esil, d / s);
			}
		}
	} else {
		ERR("esil_float_div: invalid parameters.");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_float_neg(RAnalEsil *esil) {
	bool ret = false;
	double s;
	char *src = r_anal_esil_pop(esil);

	if (src)	{
		if (esil_get_parm_float(esil, src, &s)) {
			ret = esil_pushnum_float(esil, -s);
		} else {
			ERR("esil_float_neg: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_float_neg: fail to get element from stack.");
	}
	return ret;
}

static bool esil_float_ceil(RAnalEsil *esil) {
	bool ret = false;
	double s;
	char *src = r_anal_esil_pop(esil);

	if (src) {
		if (esil_get_parm_float(esil, src, &s)) {
			if (isnan(s)) {
				ret = esil_pushnum_float(esil, s);
			} else {
				ret = esil_pushnum_float(esil, ceil(s));
			}
		} else {
			ERR("esil_float_ceil: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_float_ceil: fail to get element from stack.");
	}
	return ret;
}

static bool esil_float_floor(RAnalEsil *esil) {
	bool ret = false;
	double s;
	char *src = r_anal_esil_pop(esil);

	if (src) {
		if (esil_get_parm_float(esil, src, &s)) {
			if (isnan(s)) {
				ret = esil_pushnum_float(esil, s);
			} else {
				ret = esil_pushnum_float(esil, floor(s));
			}
		} else {
			ERR("esil_float_floor: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_float_floor: fail to get element from stack.");
	}

	return ret;
}

static bool esil_float_round(RAnalEsil *esil) {
	bool ret = false;
	double s;
	char *src = r_anal_esil_pop(esil);

	if (src) {
		if (esil_get_parm_float(esil, src, &s)) {
			if (isnan(s)) {
				ret = esil_pushnum_float(esil, s);
			} else {
				ret = esil_pushnum_float(esil, round(s));
			}
		} else {
			ERR("esil_float_round: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_float_round: fail to get element from stack.");
	}
	return ret;
}

static bool esil_float_sqrt(RAnalEsil *esil) {
	bool ret = false;
	double s;
	char *src = r_anal_esil_pop(esil);

	if (src) {
		if (esil_get_parm_float(esil, src, &s)) {
			if (isnan(s)) {
				ret = esil_pushnum_float(esil, s);
			} else {
				ret = esil_pushnum_float(esil, sqrt(s));
			}
		} else {
			ERR("esil_float_sqrt: invalid parameters.");
		}
		free(src);
	} else {
		ERR("esil_float_sqrt: fail to get element from stack.");
	}
	return ret;
}

static bool iscommand(RAnalEsil *esil, const char *word, RAnalEsilOp **op) {
	RAnalEsilOp *eop = r_anal_esil_get_op (esil, word);
	if (eop) {
		*op = eop;
		return true;
	}
	return false;
}

static bool runword(RAnalEsil *esil, const char *word) {
	RAnalEsilOp *op = NULL;
	if (!word) {
		return false;
	}
	esil->parse_goto_count--;
	if (esil->parse_goto_count < 1) {
		ERR ("ESIL infinite loop detected\n");
		esil->trap = 1;       // INTERNAL ERROR
		esil->parse_stop = 1; // INTERNAL ERROR
		return false;
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
		char *if_buf = esil->Reil->if_buf;
		size_t n = strlen (if_buf);
		snprintf (if_buf + n, sizeof (esil->Reil->if_buf) - n, "%s,", word);
		if (!strcmp (word, "}")) {
			r_anal_esil_pushnum (esil, esil->Reil->addr + esil->Reil->cmd_count + 1);
			r_anal_esil_parse (esil, esil->Reil->if_buf);
		} else if (iscommand (esil, word, &op)) {
			esil->Reil->cmd_count++;
		}
		return true;
	}

	//eprintf ("WORD (%d) (%s)\n", esil->skip, word);
	if (!strcmp (word, "}{")) {
		if (esil->skip == 1) {
			esil->skip = 0;
		} else if (esil->skip == 0) {	//this isn't perfect, but should work for valid esil
			esil->skip = 1;
		}
		return true;
	}
	if (!strcmp (word, "}")) {
		if (esil->skip) {
			esil->skip--;
		}
		return true;
	}
	if (esil->skip && strcmp(word, "?{")) {
		return true;
	}

	if (iscommand (esil, word, &op)) {
		// run action
		if (op) {
			if (esil->cb.hook_command) {
				if (esil->cb.hook_command (esil, word)) {
					return 1; // XXX cannot return != 1
				}
			}
			esil->current_opstr = strdup (word);
			//so this is basically just sharing what's the operation with the operation
			//useful for wrappers
			const bool ret = op->code (esil);
			free (esil->current_opstr);
			esil->current_opstr = NULL;
			if (!ret) {
				if (esil->verbose) {
					eprintf ("%s returned 0\n", word);
				}
			}
			return ret;
		}
	}
	if (!*word || *word == ',') {
		// skip empty words
		return true;
	}

	// push value
	if (!r_anal_esil_push (esil, word)) {
		ERR ("ESIL stack is full");
		esil->trap = 1;
		esil->trap_code = 1;
	}
	return true;
}

static const char *gotoWord(const char *str, int n) {
	const char *ostr = str;
	int count = 0;
	while (*str) {
		if (count == n) {
			return ostr;
		}
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
	r_return_val_if_fail (esil && str, 0);
	if (!*str) {
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
			eprintf ("[esil at 0x%08"PFMT64x"] TODO: %s\n", esil->address, *str + 1);
		}
		return 1;
	}
	return 3;
}

static bool __stepOut(RAnalEsil *esil, const char *cmd) {
	static bool inCmdStep = false;
	if (cmd && esil && esil->cmd && !inCmdStep) {
		inCmdStep = true;
		if (esil->cmd (esil, cmd, esil->address, 0)) {
			inCmdStep = false;
			// if returns 1 we skip the impl
			return true;
		}
		inCmdStep = false;
	}
	return false;
}

R_API bool r_anal_esil_parse(RAnalEsil *esil, const char *str) {
	int wordi = 0;
	int dorunword;
	char word[64];
	const char *ostr = str;
	r_return_val_if_fail (esil && R_STR_ISNOTEMPTY (str), 0);

	if (__stepOut (esil, esil->cmd_step)) {
		(void)__stepOut (esil, esil->cmd_step_out);
		return true;
	}
	const char *hashbang = strstr (str, "#!");
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
// memleak or failing aetr test. wat du
//	r_anal_esil_stack_free (esil);
	esil->parse_goto_count = esil->anal? esil->anal->esil_goto_limit: R_ANAL_ESIL_GOTO_LIMIT;
	str = ostr;
repeat:
	wordi = 0;
	while (*str) {
		if (str == hashbang) {
			if (esil->anal && esil->anal->coreb.setab) {
				esil->anal->coreb.cmd (esil->anal->coreb.core, str + 2);
			}
			break;
		}
		if (wordi > 62) {
			ERR ("Invalid esil string");
			__stepOut (esil, esil->cmd_step_out);
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
					__stepOut (esil, esil->cmd_step_out);
					return 0;
				}
				word[wordi] = ',';
				wordi = 0;
				switch (evalWord (esil, ostr, &str)) {
				case 0: goto loop;
				case 1:
					__stepOut (esil, esil->cmd_step_out);
					return 0;
				case 2: continue;
				}
				if (dorunword == 1) {
					__stepOut (esil, esil->cmd_step_out);
					return 0;
				}
			}
			str++;
		}
		word[wordi++] = *str;
		//is *str is '\0' in the next iteration the condition will be true
		//reading beyond the boundaries
		if (*str) {
			str++;
		}
	}
	word[wordi] = 0;
	if (*word) {
		if (!runword (esil, word)) {
			__stepOut (esil, esil->cmd_step_out);
			return 0;
		}
		switch (evalWord (esil, ostr, &str)) {
		case 0: goto loop;
		case 1: __stepOut (esil, esil->cmd_step_out);
			return 0;
		case 2: goto repeat;
		}
	}
	__stepOut (esil, esil->cmd_step_out);
	return 1;
}

R_API bool r_anal_esil_runword(RAnalEsil *esil, const char *word) {
	const char *str = NULL;
	(void)runword (esil, word);
	if (*word) {
		if (!runword (esil, word)) {
			return false;
		}
		int ew = evalWord (esil, word, &str);
		eprintf ("ew %d\n", ew);
		eprintf ("--> %s\n", r_str_getf (str));
	}
	return true;
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
	while (*str == ' ') {
		str++; // use proper string chop?
	}
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
		eprintf ("Warning: Cannot pop because The ESIL stack is empty");
		return -1;
	}
	return ret;
}

static void r_anal_esil_setup_ops(RAnalEsil *esil) {
#define OP(v, w, x, y, z) r_anal_esil_set_op (esil, v, w, x, y, z)
#define	OT_UNK	R_ANAL_ESIL_OP_TYPE_UNKNOWN
#define	OT_CTR	R_ANAL_ESIL_OP_TYPE_CONTROL_FLOW
#define	OT_MATH	R_ANAL_ESIL_OP_TYPE_MATH
#define	OT_REGW	R_ANAL_ESIL_OP_TYPE_REG_WRITE
#define	OT_MEMW	R_ANAL_ESIL_OP_TYPE_MEM_WRITE
#define	OT_MEMR	R_ANAL_ESIL_OP_TYPE_MEM_READ

	OP ("$", esil_interrupt, 0, 1, OT_UNK);		//hm, type seems a bit wrong
	OP ("()", esil_syscall, 0, 1, OT_UNK);		//same
	OP ("$z", esil_zf, 1, 0, OT_UNK);
	OP ("$c", esil_cf, 1, 1, OT_UNK);
	OP ("$b", esil_bf, 1, 1, OT_UNK);
	OP ("$p", esil_pf, 1, 0, OT_UNK);
	OP ("$s", esil_sf, 1, 1, OT_UNK);
	OP ("$o", esil_of, 1, 1, OT_UNK);
	OP ("$ds", esil_ds, 1, 0, OT_UNK);
	OP ("$jt", esil_jt, 1, 0, OT_UNK);
	OP ("$js", esil_js, 1, 0, OT_UNK);
	OP ("$r", esil_rs, 1, 0, OT_UNK);
	OP ("$$", esil_address, 1, 0, OT_UNK);
	OP ("~", esil_signext, 1, 2, OT_MATH);
	OP ("~=", esil_signexteq, 0, 2, OT_MATH);
	OP ("==", esil_cmp, 0, 2, OT_MATH);
	OP ("<", esil_smaller, 1, 2, OT_MATH);
	OP (">", esil_bigger, 1, 2, OT_MATH);
	OP ("<=", esil_smaller_equal, 1, 2, OT_MATH);
	OP (">=", esil_bigger_equal, 1, 2, OT_MATH);
	OP ("?{", esil_if, 0, 1, OT_CTR);
	OP ("<<", esil_lsl, 1, 2, OT_MATH);
	OP ("<<=", esil_lsleq, 0, 2, OT_MATH | OT_REGW);
	OP (">>", esil_lsr, 1, 2, OT_MATH);
	OP (">>=", esil_lsreq, 0, 2, OT_MATH | OT_REGW);
	OP (">>>>", esil_asr, 1, 2, OT_MATH);
	OP (">>>>=", esil_asreq, 0, 2, OT_MATH | OT_REGW);
	OP (">>>", esil_ror, 1, 2, OT_MATH);
	OP ("<<<", esil_rol, 1, 2, OT_MATH);
	OP ("&", esil_and, 1, 2, OT_MATH);
	OP ("&=", esil_andeq, 0, 2, OT_MATH | OT_REGW);
	OP ("}", esil_nop, 0, 0, OT_CTR); // just to avoid push
	OP ("}{", esil_nop, 0, 0, OT_CTR);
	OP ("|", esil_or, 1, 2, OT_MATH);
	OP ("|=", esil_oreq, 0, 2, OT_MATH | OT_REGW);
	OP ("!", esil_neg, 1, 1, OT_MATH);
	OP ("!=", esil_negeq, 0, 1, OT_MATH | OT_REGW);
	OP ("=", esil_eq, 0, 2, OT_REGW);
	OP (":=", esil_weak_eq, 0, 2, OT_REGW);
	OP ("L*", esil_long_mul, 2, 2, OT_MATH);
	OP ("*", esil_mul, 1, 2, OT_MATH);
	OP ("*=", esil_muleq, 0, 2, OT_MATH | OT_REGW);
	OP ("^", esil_xor, 1, 2, OT_MATH);
	OP ("^=", esil_xoreq, 0, 2, OT_MATH | OT_REGW);
	OP ("+", esil_add, 1, 2, OT_MATH);
	OP ("+=", esil_addeq, 0, 2, OT_MATH | OT_REGW);
	OP ("++", esil_inc, 1, 1, OT_MATH);
	OP ("++=", esil_inceq, 0, 1, OT_MATH | OT_REGW);
	OP ("-", esil_sub, 1, 2, OT_MATH);
	OP ("-=", esil_subeq, 0, 2, OT_MATH | OT_REGW);
	OP ("--", esil_dec, 1, 1, OT_MATH);
	OP ("--=", esil_deceq, 0, 1, OT_MATH | OT_REGW);
	OP ("/", esil_div, 1, 2, OT_MATH);
	OP ("~/", esil_signed_div, 1, 2, OT_MATH);
	OP ("/=", esil_diveq, 0, 2, OT_MATH | OT_REGW);
	OP ("%", esil_mod, 1, 2, OT_MATH);
	OP ("~%", esil_signed_mod, 1, 2, OT_MATH);
	OP ("%=", esil_modeq, 0, 2, OT_MATH | OT_REGW);
	OP ("=[]", esil_poke, 0, 2, OT_MEMW);
	OP ("=[1]", esil_poke1, 0, 2, OT_MEMW);
	OP ("=[2]", esil_poke2, 0, 2, OT_MEMW);
	OP ("=[3]", esil_poke3, 0, 2, OT_MEMW);
	OP ("=[4]", esil_poke4, 0, 2, OT_MEMW);
	OP ("=[8]", esil_poke8, 0, 2, OT_MEMW);
	OP ("=[16]", esil_poke16, 0, 2, OT_MEMW);
	OP ("|=[]", esil_mem_oreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("|=[1]", esil_mem_oreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("|=[2]", esil_mem_oreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("|=[4]", esil_mem_oreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("|=[8]", esil_mem_oreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("^=[]", esil_mem_xoreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("^=[1]", esil_mem_xoreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("^=[2]", esil_mem_xoreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("^=[4]", esil_mem_xoreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("^=[8]", esil_mem_xoreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("&=[]", esil_mem_andeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("&=[1]", esil_mem_andeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("&=[2]", esil_mem_andeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("&=[4]", esil_mem_andeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("&=[8]", esil_mem_andeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("+=[]", esil_mem_addeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("+=[1]", esil_mem_addeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("+=[2]", esil_mem_addeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("+=[4]", esil_mem_addeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("+=[8]", esil_mem_addeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("-=[]", esil_mem_subeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("-=[1]", esil_mem_subeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("-=[2]", esil_mem_subeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("-=[4]", esil_mem_subeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("-=[8]", esil_mem_subeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("%=[]", esil_mem_modeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("%=[1]", esil_mem_modeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("%=[2]", esil_mem_modeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("%=[4]", esil_mem_modeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("%=[8]", esil_mem_modeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("/=[]", esil_mem_diveq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("/=[1]", esil_mem_diveq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("/=[2]", esil_mem_diveq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("/=[4]", esil_mem_diveq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("/=[8]", esil_mem_diveq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("*=[]", esil_mem_muleq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("*=[1]", esil_mem_muleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("*=[2]", esil_mem_muleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("*=[4]", esil_mem_muleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("*=[8]", esil_mem_muleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("++=[]", esil_mem_inceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("++=[1]", esil_mem_inceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("++=[2]", esil_mem_inceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("++=[4]", esil_mem_inceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("++=[8]", esil_mem_inceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("--=[]", esil_mem_deceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("--=[1]", esil_mem_deceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("--=[2]", esil_mem_deceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("--=[4]", esil_mem_deceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("--=[8]", esil_mem_deceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("<<=[]", esil_mem_lsleq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("<<=[1]", esil_mem_lsleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("<<=[2]", esil_mem_lsleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("<<=[4]", esil_mem_lsleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("<<=[8]", esil_mem_lsleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP (">>=[]", esil_mem_lsreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP (">>=[1]", esil_mem_lsreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP (">>=[2]", esil_mem_lsreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP (">>=[4]", esil_mem_lsreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP (">>=[8]", esil_mem_lsreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP ("[]", esil_peek, 1, 1, OT_MEMR);
	OP ("[*]", esil_peek_some, 0, 0, OT_MEMR);
	OP ("=[*]", esil_poke_some, 0, 0, OT_MEMW);
	OP ("[1]", esil_peek1, 1, 1, OT_MEMR);
	OP ("[2]", esil_peek2, 1, 1, OT_MEMR);
	OP ("[3]", esil_peek3, 1, 1, OT_MEMR);
	OP ("[4]", esil_peek4, 1, 1, OT_MEMR);
	OP ("[8]", esil_peek8, 1, 1, OT_MEMR);
	OP ("[16]", esil_peek16, 1, 1, OT_MEMR);
	OP ("STACK", r_anal_esil_dumpstack, 0, 0, OT_UNK);
	OP ("REPEAT", esil_repeat, 0, 2, OT_CTR);
	OP ("POP", esil_pop, 0, 1, OT_UNK);
	OP ("TODO", esil_todo, 0, 0, OT_UNK);
	OP ("GOTO", esil_goto, 0, 1, OT_CTR);
	OP ("BREAK", esil_break, 0, 0, OT_CTR);
	OP ("CLEAR", esil_clear, 0, 0, OT_UNK);
	OP ("DUP", esil_dup, 1, 0, OT_UNK);
	OP ("NUM", esil_num, 1, 1, OT_UNK);
	OP ("SWAP", esil_swap, 2, 2, OT_UNK);
	OP ("TRAP", esil_trap, 0, 0, OT_UNK);
	OP ("BITS", esil_bits, 1, 0, OT_UNK);
	OP ("SETJT", esil_set_jump_target, 0, 1, OT_UNK);
	OP ("SETJTS", esil_set_jump_target_set, 0, 1, OT_UNK);
	OP ("SETD", esil_set_delay_slot, 0, 1, OT_UNK);

	/* we all float down here */
	OP ("NAN", esil_is_nan, 1, 1, OT_MATH);
	OP ("I2D", esil_signed_to_double, 1, 1, OT_MATH);
	OP ("S2D", esil_signed_to_double, 1, 1, OT_MATH);
	OP ("U2D", esil_unsigned_to_double, 1, 1, OT_MATH);
	OP ("D2I", esil_double_to_int, 1, 1, OT_MATH);
	OP ("D2F", esil_double_to_float, 1, 2, OT_MATH);
	OP ("F2D", esil_float_to_double, 1, 2, OT_MATH);
	OP ("F==", esil_float_cmp, 1, 2, OT_MATH);
	OP ("F!=", esil_float_negcmp, 1, 2, OT_MATH);
	OP ("F<", esil_float_less, 1, 2, OT_MATH);
	OP ("F<=", esil_float_lesseq, 1, 2, OT_MATH);
	OP ("F+", esil_float_add, 1, 2, OT_MATH);
	OP ("F-", esil_float_sub, 1, 2, OT_MATH);
	OP ("F*", esil_float_mul, 1, 2, OT_MATH);
	OP ("F/", esil_float_div, 1, 2, OT_MATH);
	OP ("-F", esil_float_neg, 1, 1, OT_MATH);
	OP ("CEIL", esil_float_ceil, 1, 1, OT_MATH);
	OP ("FLOOR", esil_float_floor, 1, 1, OT_MATH);
	OP ("ROUND", esil_float_round, 1, 1, OT_MATH);
	OP ("SQRT", esil_float_sqrt, 1, 1, OT_MATH);

}

/* register callbacks using this anal module. */
R_API bool r_anal_esil_setup(RAnalEsil *esil, RAnal *anal, int romem, int stats, int nonull) {
	r_return_val_if_fail (esil, false);
	//esil->debug = 0;
	esil->anal = anal;
	esil->parse_goto_count = anal->esil_goto_limit;
	esil->trap = 0;
	esil->trap_code = 0;
	//esil->user = NULL;
	esil->cb.reg_read = internal_esil_reg_read;
	esil->cb.mem_read = internal_esil_mem_read;

	if (nonull) {
		// this is very questionable, most platforms allow accessing NULL
		// never writes zero to PC, BP, SP, why? because writing
		// zeros to these registers is equivalent to accessing NULL
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

	return (anal->cur && anal->cur->esil_init)
		? anal->cur->esil_init (esil): true;
}
