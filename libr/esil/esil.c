/* radare - LGPL - Copyright 2014-2024 - pancake, condret */

#define R_LOG_ORIGIN "esil"

#include <r_anal.h>
#include <r_io.h>
#include <r_reg.h>

// TODO: replace esil->verbose with R_LOG_DEBUG
#define IFDBG if (esil->verbose > 1)
R_IPI bool isregornum(REsil *esil, const char *str, ut64 *num);

R_IPI bool alignCheck(REsil *esil, ut64 addr) {
	// r_anal_archinfo (esil->anal, R_ARCH_INFO_DATA_ALIGN);
	const ut32 da = esil->data_align;
	return !(da > 0 && addr % da);
}

static void esil_ops_free(HtPPKv *kv) {
	if (R_LIKELY (kv)) {
		free (kv->key);
		free (kv->value);
	}
}

R_API REsil *r_esil_new(int stacksize, int iotrap, unsigned int addrsize) {
	REsil *esil = R_NEW0 (REsil);
	if (stacksize < 4) {
		R_LOG_ERROR ("Esil stacksize must be at least 4 bytes");
		free (esil);
		return NULL;
	}
	esil->stack = calloc (sizeof (char *), stacksize);
	if (!esil->stack) {
		free (esil);
		return NULL;
	}
	esil->verbose = false;
	esil->stacksize = stacksize;
	esil->parse_goto_count = R_ESIL_GOTO_LIMIT;
	esil->ops = ht_pp_new (NULL, esil_ops_free, NULL);
	esil->iotrap = iotrap;
	r_esil_handlers_init (esil);
	r_esil_plugins_init (esil);
	esil->addrmask = r_num_genmask (addrsize - 1);
	esil->trace = r_esil_trace_new (esil);
#if USE_NEW_ESIL == 0
	int stats = 1;
	r_esil_stats (esil, NULL, stats);
#endif
	r_esil_setup_ops (esil);
	return esil;
}

R_API bool r_esil_init(REsil *esil, int stacksize, bool iotrap,
	ut32 addrsize, REsilRegInterface *reg_if, REsilMemInterface *mem_if) {
	R_RETURN_VAL_IF_FAIL (esil && reg_if && reg_if->is_reg && reg_if->reg_read &&
		reg_if->reg_write && reg_if->reg_size && mem_if && mem_if->mem_read &&
		mem_if->mem_write && (stacksize > 2), false);
	//do not check for mem_switch, as that is optional
	esil->stack = calloc (sizeof (char *), stacksize);
	if (R_UNLIKELY (!esil->stack)) {
		return false;
	}
	esil->ops = ht_pp_new (NULL, esil_ops_free, NULL);
	if (R_UNLIKELY (!esil->ops)) {
		goto ops_fail;
	}
	if (R_UNLIKELY (!r_esil_setup_ops (esil) || !r_esil_handlers_init (esil))) {
		goto ops_setup_fail;
	}
	if (R_UNLIKELY (!r_esil_plugins_init (esil))) {
		goto plugins_fail;
	}
	int i;
	for (i = 0; i < R_ESIL_VOYEUR_LAST; i++) {
		if (r_id_storage_init (&esil->voyeur[i], 0, MAX_VOYEURS)) {
			continue;
		}
		R_LOG_ERROR ("voyeur init failed");
		do {
			r_id_storage_fini (&esil->voyeur[i]);
			i--;
		} while (i >= 0);
		goto voyeur_fail;
	}
	//not initializing stats here, it needs get reworked and should live in anal
	//same goes for trace, probably
	esil->stacksize = stacksize;
	esil->parse_goto_count = R_ESIL_GOTO_LIMIT;
	esil->iotrap = iotrap;
	esil->addrmask = r_num_genmask (addrsize - 1);
	esil->reg_if = *reg_if;
	esil->mem_if = *mem_if;
	return true;
voyeur_fail:
	r_esil_plugins_fini (esil);
plugins_fail:
	r_esil_handlers_fini (esil);
ops_setup_fail:
	ht_pp_free (esil->ops);
ops_fail:
	free (esil->stack);
	return false;
}

R_API REsil *r_esil_new_ex(int stacksize, bool iotrap, ut32 addrsize,
	REsilRegInterface *reg_if, REsilMemInterface *mem_if) {
	REsil *esil = R_NEW0 (REsil);
	if (R_UNLIKELY (!r_esil_init (esil, stacksize, iotrap,
		addrsize, reg_if, mem_if))) {
		free (esil);
		return NULL;
	}
	return esil;
}

static bool default_is_reg(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return false;
	}
	r_unref (ri);
	return true;
}

#if 0
static bool default_reg_alias(void *reg, int kind, const char *name) {
	return r_reg_set_alias ((RReg *)reg, kind, name);
}
#endif

static bool default_reg_read(void *reg, const char *name, ut64 *val) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return false;
	}
	*val = r_reg_get_value ((RReg *)reg, ri);
	r_unref (ri);
	return true;
}

static ut32 default_reg_size(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return 0;
	}
	r_unref (ri);
	return ri->size;
}

static REsilRegInterface simple_reg_if = {
	.is_reg = default_is_reg,
	.reg_read = default_reg_read,
	.reg_write = (REsilRegWrite)r_reg_setv,
	.reg_size = default_reg_size,
	// .reg_alias = default_reg_alias
};

R_API REsil *r_esil_new_simple(ut32 addrsize, void *reg, void *iob) {
	RIOBind *bnd = iob;
	R_RETURN_VAL_IF_FAIL (reg && iob && bnd->io, NULL);
	simple_reg_if.reg = reg;
	REsilMemInterface simple_mem_if = {{bnd->io}, (REsilMemSwitch)bnd->bank_use,
		(REsilMemRead)bnd->read_at, (REsilMemWrite)bnd->write_at};
	return r_esil_new_ex (4096, false, addrsize, &simple_reg_if, &simple_mem_if);
}

R_API ut32 r_esil_add_voyeur(REsil *esil, void *user, void *vfn, REsilVoyeurType vt) {
	R_RETURN_VAL_IF_FAIL (esil && vfn, R_ESIL_VOYEUR_ERR);
	switch (vt) {
	case R_ESIL_VOYEUR_REG_READ:
	case R_ESIL_VOYEUR_REG_WRITE:
	case R_ESIL_VOYEUR_MEM_READ:
	case R_ESIL_VOYEUR_MEM_WRITE:
	case R_ESIL_VOYEUR_OP:
		break;
	default:
		R_WARN_IF_REACHED ();
		return R_ESIL_VOYEUR_ERR;
	}
	REsilVoyeur *voyeur = R_NEW (REsilVoyeur);
	if (!voyeur) {
		return R_ESIL_VOYEUR_ERR;
	}
	ut32 id;
	if (!r_id_storage_add (&esil->voyeur[vt], voyeur, &id)) {
		free (voyeur);
		return R_ESIL_VOYEUR_ERR;
	}
	voyeur->user = user;
	voyeur->vfn = vfn;
	return id | (vt << VOYEUR_SHIFT_LEFT);
}

R_API void r_esil_del_voyeur(REsil *esil, ut32 vid) {
	R_RETURN_IF_FAIL (esil);
	const ut32 vt = (vid & VOYEUR_TYPE_MASK) >> VOYEUR_SHIFT_LEFT;
	switch (vt) {
	case R_ESIL_VOYEUR_REG_READ:
	case R_ESIL_VOYEUR_REG_WRITE:
	case R_ESIL_VOYEUR_MEM_READ:
	case R_ESIL_VOYEUR_MEM_WRITE:
	case R_ESIL_VOYEUR_OP:
		break;
	default:
		R_WARN_IF_REACHED ();
		return;
	}
	const ut32 id = vid & ~VOYEUR_TYPE_MASK;
	free (r_id_storage_take (&esil->voyeur[vt], id));
}

R_API bool r_esil_set_op(REsil *esil, const char *op, REsilOpCb code, ut32 push, ut32 pop, ut32 type, const char *info) {
	R_RETURN_VAL_IF_FAIL (code && R_STR_ISNOTEMPTY (op) && esil && esil->ops, false);
	REsilOp *eop = ht_pp_find (esil->ops, op, NULL);
	if (!eop) {
		eop = R_NEW (REsilOp);
		if (!eop) {
			return false;
		}
		if (!ht_pp_insert (esil->ops, op, eop)) {
			R_LOG_ERROR ("Cannot set esil-operation %s", op);
			free (eop);
			return false;
		}
	}
	eop->push = push;
	eop->pop = pop;
	eop->type = type;
	eop->code = code;
	eop->info = info;
	return true;
}

R_API REsilOp *r_esil_get_op(REsil *esil, const char *op) {
	R_RETURN_VAL_IF_FAIL (esil && esil->ops && R_STR_ISNOTEMPTY (op), NULL);
	return (REsilOp *) ht_pp_find (esil->ops, op, NULL);
}

R_API void r_esil_del_op(REsil *esil, const char *op) {
	R_RETURN_IF_FAIL (esil && esil->ops && R_STR_ISNOTEMPTY (op));
	ht_pp_delete (esil->ops, op);
}

R_API void r_esil_set_pc(REsil *esil, ut64 addr) {
	R_RETURN_IF_FAIL (esil);
	// r_reg_set_value_by_role (esil->anal->reg, R_REG_ALIAS_PC, addr);
	esil->addr = addr;
}

R_API void r_esil_fini(REsil *esil) {
	if (!esil) {
		return;
	}
	int i;
	for (i = 0; i < R_ESIL_VOYEUR_LAST; i++) {
		r_id_storage_fini (&esil->voyeur[i]);
	}
	r_esil_plugins_fini (esil);
	r_esil_handlers_fini (esil);
	ht_pp_free (esil->ops);
	r_esil_stack_free (esil);
	free (esil->stack);
}

R_API void r_esil_free(REsil *esil) {
	if (!esil) {
		return;
	}

	// Try arch esil fini cb first, then anal as fallback
	RArchSession *as = R_UNWRAP4 (esil, anal, arch, session);
	if (as) {
		RArchPluginEsilCallback esil_cb = R_UNWRAP3 (as, plugin, esilcb);
		if (esil_cb) {
			if (!esil_cb (as, R_ARCH_ESIL_ACTION_FINI)) {
				R_LOG_DEBUG ("Failed to properly cleanup esil for arch plugin");
			}
		}
	}
	if (esil->anal && esil == esil->anal->esil) {
		esil->anal->esil = NULL;
	}
	if (as && esil == esil->anal->arch->esil) {
		esil->anal->arch->esil = NULL;
	}
	r_esil_plugins_fini (esil);
	r_esil_handlers_fini (esil);
	ht_pp_free (esil->ops);
	sdb_free (esil->stats);
	r_esil_stack_free (esil);
	free (esil->stack);

	r_esil_trace_free (esil->trace);
	free (esil->cmd_intr);
	free (esil->cmd_trap);
	free (esil->cmd_mdev);
	free (esil->cmd_todo);
	free (esil->cmd_step);
	free (esil->cmd_step_out);
	free (esil->cmd_ioer);
	free (esil->mdev_range);
	free (esil);
}

R_API bool r_esil_mem_read_silent(REsil *esil, ut64 addr, ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (buf && esil && esil->mem_if.mem_read, false);
	if (R_LIKELY (esil->mem_if.mem_read (esil->mem_if.mem, addr & esil->addrmask, buf, len))) {
		return true;
	}
	esil->trap = R_ANAL_TRAP_READ_ERR;
	esil->trap_code = addr;
	return false;
}

static bool internal_esil_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal, false);
	bool ret = false;
	if (esil->nowrite) {
		return false;
	}
	RIOBind *iob = &esil->anal->iob;
	RIO *io = iob->io;
	if (!io || addr == UT64_MAX) {
		return false;
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
	if (iob->write_at (io, addr, buf, len)) {
		ret = len;
	}
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, write_at return true/false can't be used to check error vs len
	if (!iob->is_valid_offset (io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd (esil, esil->cmd_ioer, esil->addr, 0);
		}
	}
	return ret;
}

static bool internal_esil_mem_write_no_null(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal, false);
	RIOBind *iob = &esil->anal->iob;
	RIO *io = iob->io;
	bool ret = false;
	if (!io || addr == UT64_MAX) {
		return false;
	}
	if (esil->nowrite) {
		return false;
	}
	addr &= esil->addrmask;
	if (iob->write_at (io, addr, buf, len)) {
		ret = len;
	}
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, write_at return true/false can't be used to check error vs len
	if (!iob->is_valid_offset (io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
	}
	return ret;
}

R_API bool r_esil_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
#if USE_NEW_ESIL
	R_RETURN_VAL_IF_FAIL (esil && buf && esil->mem_if.mem_write, false);
	addr &= esil->addrmask;
	union {
		ut8 buf[16];
		ut8 *ptr;
	} o;
	ut32 i;
	if (R_LIKELY (len < 17)) {
		memset (o.buf, 0xff, len);
		if (R_UNLIKELY (!r_esil_mem_read_silent (esil, addr, o.buf, len))) {
			esil->trap = R_ANAL_TRAP_NONE;
		}
		if (R_UNLIKELY (!r_esil_mem_write_silent (esil, addr, buf, len))) {
			return false;
		}
		if (!r_id_storage_get_lowest (&esil->voyeur[R_ESIL_VOYEUR_MEM_WRITE], &i)) {
			return true;
		}
		do {
			REsilVoyeur *voy = r_id_storage_get (&esil->voyeur[R_ESIL_VOYEUR_MEM_WRITE], i);
			voy->mem_write (voy->user, addr, o.buf, buf, len);
		} while (r_id_storage_get_next (&esil->voyeur[R_ESIL_VOYEUR_MEM_WRITE], &i));
		return true;
	}
	o.ptr = R_NEWS (ut8, len);
	if (R_UNLIKELY (!o.ptr)) {
		return r_esil_mem_write_silent (esil, addr, buf, len);
	}
	memset (o.ptr, 0xff, len);
	if (R_UNLIKELY (!r_esil_mem_read_silent (esil, addr, o.ptr, len))) {
		esil->trap = R_ANAL_TRAP_NONE;
	}
	if (R_UNLIKELY (!r_esil_mem_write_silent (esil, addr, buf, len))) {
		return false;
	}
	do {
		REsilVoyeur *voy = r_id_storage_get (&esil->voyeur[R_ESIL_VOYEUR_MEM_WRITE], i);
		voy->mem_write (voy->user, addr, o.ptr, buf, len);
	} while (r_id_storage_get_next (&esil->voyeur[R_ESIL_VOYEUR_MEM_WRITE], &i));
	free (o.ptr);
	return true;
#else
	R_RETURN_VAL_IF_FAIL (esil && buf, false);
	addr &= esil->addrmask;
	bool ret = false;
	IFDBG {
		eprintf ("0x%08" PFMT64x " <W ", addr);
		int i;
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
#endif
}

R_API bool r_esil_mem_write_silent(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (esil && buf && esil->mem_if.mem_write, false);
	if (R_LIKELY (esil->mem_if.mem_write (esil->mem_if.mem, addr & esil->addrmask, buf, len))) {
		return true;
	}
	esil->trap = R_ANAL_TRAP_WRITE_ERR;
	esil->trap_code = addr;
	return false;
}

static bool internal_esil_reg_read(REsil *esil, const char *regname, ut64 *num, int *size) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal, false);
	RRegItem *ri = r_reg_get (esil->anal->reg, regname, -1);
	if (ri) {
		if (size) {
			*size = ri->size;
		}
		if (num) {
			*num = r_reg_get_value (esil->anal->reg, ri);
			if (esil->verbose) {
				eprintf ("%s < %x\n", regname, (int)*num);
			}
		}
		r_unref (ri);
		return true;
	}
	return false;
}

static bool internal_esil_reg_write(REsil *esil, const char *regname, ut64 num) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal, false);
#if 1
	if (r_reg_setv (esil->anal->reg, regname, num)) {
		return true;
	}
	R_LOG_DEBUG ("Register %s does not exist", regname);
#else
	RRegItem *ri = r_reg_get (esil->anal->reg, regname, -1);
	if (ri) {
		r_reg_set_value (esil->anal->reg, ri, num);
		R_LOG_DEBUG ("%s = %x", regname, (int)num);
		r_unref (ri);
		return true;
	}
#endif
	return false;
}

//WTF IS THIS!!!
//Are you really trying to prevent the analyzed binary from doing anything that would cause it to segfault irl?
//WHY?
//	- condret
static bool internal_esil_reg_write_no_null(REsil *esil, const char *regname, ut64 num) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal && esil->anal->reg, false);
	RReg *reg = esil->anal->reg;

	const char *pc = r_reg_alias_getname (reg, R_REG_ALIAS_PC);
	const char *sp = r_reg_alias_getname (reg, R_REG_ALIAS_SP);
	const char *bp = r_reg_alias_getname (reg, R_REG_ALIAS_BP);

	if (!pc) {
		R_LOG_WARN ("RReg profile does not contain PC register");
		return false;
	}
	if (!sp) {
		R_LOG_WARN ("RReg profile does not contain SP register");
		return false;
	}
	if (!bp) {
		R_LOG_WARN ("RReg profile does not contain BP register");
		return false;
	}
	RRegItem *ri = r_reg_get (reg, regname, -1);
	if (ri && ri->name && ((strcmp (ri->name, pc) && strcmp (ri->name, sp) && strcmp (ri->name, bp)) || num)) { //I trust k-maps
		r_reg_set_value (reg, ri, num);
		r_unref (ri);
		return true;
	}
	R_LOG_DEBUG ("Register %s does not exist", regname);
	// assert trap in esil
	r_unref (ri);
	return false;
}

R_API bool r_esil_pushnum(REsil *esil, ut64 num) {
	char str[SDB_NUM_BUFSZ] = {0};
	sdb_itoa (num, 16, str, sizeof (str));
	return r_esil_push (esil, str);
}

R_API bool r_esil_push(REsil *esil, const char *str) {
	R_RETURN_VAL_IF_FAIL (esil && R_STR_ISNOTEMPTY (str), false);
	if (esil->stackptr > (esil->stacksize - 1)) {
		return false;
	}
	esil->stack[esil->stackptr++] = strdup (str);
	return true;
}

R_API char *r_esil_pop(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, NULL);
	if (esil->stackptr < 1) {
		return NULL;
	}
	return esil->stack[--esil->stackptr];
}

static int not_a_number(REsil *esil, const char *str) {
	RRegItem *ri = r_reg_get (esil->anal->reg, str, -1);
	if (ri) {
		r_unref (ri);
		return R_ESIL_PARM_REG;
	}
	return R_ESIL_PARM_INVALID;
}

R_API int r_esil_get_parm_type(REsil *esil, const char *str) {
	R_RETURN_VAL_IF_FAIL (esil && str, R_ESIL_PARM_INVALID);
	if (R_STR_ISEMPTY (str)) {
		return R_ESIL_PARM_INVALID;
	}
	if (r_str_startswith (str, "0x")) {
		return R_ESIL_PARM_NUM;
	}
	if (!((isdigit(str[0])) || str[0] == '-')) {
		return not_a_number (esil, str);
	}
	size_t i;
	for (i = 1; str[i]; i++) {
		if (!isdigit (str[i])) {
			return not_a_number (esil, str);
		}
	}
	return R_ESIL_PARM_NUM;
}

R_API bool r_esil_get_parm_size(REsil *esil, const char *str, ut64 *num, int *size) {
	R_RETURN_VAL_IF_FAIL (esil && num, false);
	if (size) {
		*size = 0;
	}
	if (R_STR_ISEMPTY (str)) {
		return false;
	}
	const int parm_type = r_esil_get_parm_type (esil, str);
	switch (parm_type) {
	case R_ESIL_PARM_NUM:
		*num = r_num_get (NULL, str);
		if (size) {
			*size = esil->anal->config->bits;
		}
		return true;
	case R_ESIL_PARM_REG:
		return r_esil_reg_read (esil, str, num, (ut32 *)size);
	default:
		R_LOG_DEBUG ("Invalid esil arg to find parm size (%s)", str);
		esil->parse_stop = 1;
		return false;
	}
}

// XXX deprecate
R_API int r_esil_get_parm(REsil *esil, const char *str, ut64 *num) {
	return r_esil_get_parm_size (esil, str, num, NULL);
}

R_API bool r_esil_reg_write(REsil *esil, const char *dst, ut64 val) {
	R_RETURN_VAL_IF_FAIL (esil && dst, false);
#if USE_NEW_ESIL
	ut64 old;
	if (R_UNLIKELY (!r_esil_reg_read_silent (esil, dst, &old, NULL))) {
		return r_esil_reg_write_silent (esil, dst, val);
	}
	if (R_UNLIKELY (!r_esil_reg_write_silent (esil, dst, val))) {
		return false;
	}
	ut32 i;
	if (!r_id_storage_get_lowest (&esil->voyeur[R_ESIL_VOYEUR_REG_WRITE], &i)) {
		return true;
	}
	do {
		REsilVoyeur *voy = r_id_storage_get (&esil->voyeur[R_ESIL_VOYEUR_REG_WRITE], i);
		voy->reg_write (voy->user, dst, old, val);
	} while (r_id_storage_get_next (&esil->voyeur[R_ESIL_VOYEUR_REG_WRITE], &i));
	return true;
#else
	bool ret = false;
	R_LOG_DEBUG ("%s=0x%" PFMT64x, dst, val);
	if (esil->cb.hook_reg_write) {
		ret = esil->cb.hook_reg_write (esil, dst, &val);
	}
	if (!ret && esil->cb.reg_write) {
		ret = esil->cb.reg_write (esil, dst, val);
	}
	return ret;
#endif
}

R_API bool r_esil_reg_write_silent(REsil *esil, const char *name, ut64 num) {
	R_RETURN_VAL_IF_FAIL (esil && name && esil->reg_if.reg_write, false);
	return esil->reg_if.reg_write (esil->reg_if.reg, name, num);
}

R_API bool r_esil_reg_read_nocallback(REsil *esil, const char *regname, ut64 *num, int *size) {
	void *old_hook_reg_read = (void *) esil->cb.hook_reg_read;
	esil->cb.hook_reg_read = NULL;
	bool ret = r_esil_reg_read (esil, regname, num, (ut32 *)size);
	esil->cb.hook_reg_read = old_hook_reg_read;
	return ret;
}

R_API bool r_esil_reg_read(REsil *esil, const char *regname, ut64 *val, ut32 *size) {
#if USE_NEW_ESIL
	R_RETURN_VAL_IF_FAIL (esil && regname && val, false);
	if (R_UNLIKELY (!r_esil_reg_read_silent (esil, regname, val, size))) {
		return false;
	}
	ut32 i;
	if (!r_id_storage_get_lowest (&esil->voyeur[R_ESIL_VOYEUR_REG_READ], &i)) {
		return true;
	}
	do {
		REsilVoyeur *voy = r_id_storage_get (&esil->voyeur[R_ESIL_VOYEUR_REG_READ], i);
		voy->reg_read (voy->user, regname, *val);
	} while (r_id_storage_get_next (&esil->voyeur[R_ESIL_VOYEUR_REG_READ], &i));
	return true;
#else
	R_RETURN_VAL_IF_FAIL (esil && regname, false);
	bool ret = false;
	ut64 localnum = 0LL; // XXX why is this necessary?
	if (!val) {
		val = &localnum;
	}
	*val = 0LL;
	if (size) {
		*size = esil->anal->config->bits;
	}
	if (esil->cb.hook_reg_read) {
		ret = esil->cb.hook_reg_read (esil, regname, val, (st32 *)size);
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read (esil, regname, val, (st32 *)size);
	}
	return ret;
#endif
}

R_API bool r_esil_reg_read_silent(REsil *esil, const char *name, ut64 *val, ut32 *size) {
	R_RETURN_VAL_IF_FAIL (esil && esil->reg_if.reg_read && name && val, false);
	if (!esil->reg_if.reg_read (esil->reg_if.reg, name, val)) {
		return false;
	}
	if (esil->reg_if.reg_size && size) {
		*size = esil->reg_if.reg_size (esil->reg_if.reg, name);
	}
	return true;
}

R_API const char *r_esil_trapstr(int type) {
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

R_API bool r_esil_dumpstack(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	int i;
	if (esil->trap) {
		R_LOG_INFO ("ESIL TRAP type %d code 0x%08x %s",
			esil->trap, esil->trap_code,
			r_esil_trapstr (esil->trap));
	}
	bool ret = false;
	for (i = 0; i < esil->stackptr; i++) {
		const char *comma = (i + 1 < esil->stackptr)? ",": "\n";
		esil->anal->cb_printf ("%s%s", esil->stack[i], comma);
		ret = true;
	}
	return ret;
}

static bool runword(REsil *esil, const char *word) {
	REsilOp *op = NULL;
	if (!word) {
		return false;
	}
	esil->parse_goto_count--;
	if (esil->parse_goto_count < 1) {
		R_LOG_DEBUG ("ESIL infinite loop detected");
		esil->trap = 1;       // INTERNAL ERROR
		esil->parse_stop = 1; // INTERNAL ERROR
		return false;
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
	if (esil->skip && strcmp (word, "?{")) {
		return true;
	}

	op = r_esil_get_op (esil, word);
	if (op) {
		// run action
#if USE_NEW_ESIL
		ut32 i;
		if (r_id_storage_get_lowest (&esil->voyeur[R_ESIL_VOYEUR_OP], &i)) {
			do {
				REsilVoyeur *voy = r_id_storage_get (&esil->voyeur[R_ESIL_VOYEUR_OP], i);
				voy->op (voy->user, word);
			} while (r_id_storage_get_next (&esil->voyeur[R_ESIL_VOYEUR_OP], &i));
		}
#else
		if (esil->cb.hook_command) {
			if (esil->cb.hook_command (esil, word)) {
				return 1; // XXX cannot return != 1
			}
		}
#endif
		esil->current_opstr = strdup (word);
		// so this is basically just sharing what's the
		// operation with the operation useful for wrappers
		const bool ret = op->code (esil);
		R_FREE (esil->current_opstr);
		if (!ret) {
			R_LOG_DEBUG ("%s returned 0", word);
		}
		return ret;
	}
	if (!*word || *word == ',') {
		// skip empty words
		return true;
	}

	// push value
	if (!r_esil_push (esil, word)) {
		R_LOG_DEBUG ("ESIL stack is full");
		esil->trap = 1;
		esil->trap_code = 1;
	}
	return true;
}

static const char *goto_word(const char *str, int n) {
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
static int eval_word(REsil *esil, const char *ostr, const char **str) {
	R_RETURN_VAL_IF_FAIL (esil && str, 0);
	if (!*str) {
		return 0;
	}
	if ((*str)[0] && (*str)[1] == ',') {
		return 2;
	}
	if (esil->parse_goto != -1) {
		// TODO: detect infinite loop??? how??
		*str = goto_word (ostr, esil->parse_goto);
		if (*str) {
			esil->parse_goto = -1;
			return 2;
		}
		if (esil->verbose) {
			R_LOG_ERROR ("Cannot find word %d", esil->parse_goto);
		}
		return 1;
	}
	if (esil->parse_stop) {
		if (esil->parse_stop == 2) {
			R_LOG_DEBUG ("[esil at 0x%08"PFMT64x"] TODO: %s", esil->addr, *str + 1);
		}
		return 1;
	}
	return 3;
}

static bool step_out(REsil *esil, const char *cmd) {
	if (cmd && esil && esil->cmd && !esil->in_cmd_step) {
		esil->in_cmd_step = true;
		if (esil->cmd (esil, cmd, esil->addr, 0)) {
			esil->in_cmd_step = false;
			// if returns 1 we skip the impl
			return true;
		}
		esil->in_cmd_step = false;
	}
	return false;
}

R_API bool r_esil_parse(REsil *esil, const char *str) {
	R_RETURN_VAL_IF_FAIL (esil, false);
#if 0
	if (strstr (str, "(null)")) {
		R_LOG_WARN ("-> 0x%"PFMT64x" %s", esil->address, str);
		r_sys_breakpoint ();
	}
#endif
	int rc = 0;
	int wordi = 0;
	int dorunword;
	char word[64];
	const char *ostr = str;
	if (R_STR_ISEMPTY (str)) {
		return false;
	}

	if (step_out (esil, esil->cmd_step)) {
		(void)step_out (esil, esil->cmd_step_out);
		return true;
	}
	esil->trap = 0;
	if (esil->cmd && esil->cmd_todo) {
		if (r_str_startswith (str, "TODO")) {
			esil->cmd (esil, esil->cmd_todo, esil->addr, 0);
		}
	}
loop:
	esil->skip = 0;
	esil->parse_goto = -1;
	esil->parse_stop = 0;
// memleak or failing aetr test. wat du
//	r_esil_stack_free (esil);
	esil->parse_goto_count = esil->anal? esil->anal->esil_goto_limit: R_ESIL_GOTO_LIMIT;
	str = ostr;
repeat:
	wordi = 0;
	while (*str) {
		if (R_UNLIKELY (wordi > 62)) {
			R_LOG_DEBUG ("Invalid esil string");
			step_out (esil, esil->cmd_step_out);
			return -1;
		}
		dorunword = 0;
		if (*str == ';') {
			word[wordi] = 0;
			dorunword = 1;
		} else if (*str == ',') {
			word[wordi] = 0;
			dorunword = 2;
		}
		if (dorunword) {
			if (*word) {
				if (!runword (esil, word)) {
					goto step_out;
				}
				word[wordi] = ',';
				wordi = 0;
				switch (eval_word (esil, ostr, &str)) {
				case 0: goto loop;
				case 1: goto step_out;
				case 2: continue;
				}
				if (dorunword == 1) {
					goto step_out;
				}
			}
			str++;
		}
		const char str0 = *str;
		word[wordi++] = str0;
		// is *str is '\0' in the next iteration the condition will be true
		// reading beyond the boundaries
		if (str0) {
			str++;
		}
	}
	word[wordi] = 0;
	if (*word) {
		if (!runword (esil, word)) {
			goto step_out;
		}
		switch (eval_word (esil, ostr, &str)) {
		case 0: goto loop;
		case 1: goto step_out;
		case 2: goto repeat;
		}
	}
	rc = 1;
step_out:
	step_out (esil, esil->cmd_step_out);
	return rc;
}

R_API bool r_esil_runword(REsil *esil, const char *word) {
	const char *str = NULL;
	if (runword (esil, word)) {
		(void)eval_word (esil, word, &str);
		return true;
	}
	return false;
}

// TODO rename to clearstack() or reset_stack()
R_API void r_esil_stack_free(REsil *esil) {
	R_RETURN_IF_FAIL (esil);
	int i;
	for (i = 0; i < esil->stackptr; i++) {
		R_TAG_FREE (esil->stack[i]);
		esil->stack[i] = NULL;
	}
	esil->stackptr = 0;
}

R_API int r_esil_condition(REsil *esil, const char *str) {
	R_RETURN_VAL_IF_FAIL (esil, -1);
	int ret = -1;
	str = r_str_trim_head_ro (str);
	(void) r_esil_parse (esil, str);
	char *popped = r_esil_pop (esil);
	if (popped) {
		ut64 num;
		if (isregornum (esil, popped, &num)) {
			ret = !!num;
		} else {
			ret = 0;
		}
		free (popped);
	} else {
		R_LOG_WARN ("Cannot pop because The ESIL stack is empty");
		return -1;
	}
	return ret;
}

static bool internal_esil_mem_read_no_null(REsil *esil, ut64 addr, ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal, false);
	RIOBind *iob = &esil->anal->iob;
	RIO *io = iob->io;
	if (!io || addr == UT64_MAX) {
		return false;
	}

	addr &= esil->addrmask;
	if (!alignCheck (esil, addr)) {
		esil->trap = R_ANAL_TRAP_READ_ERR;
		esil->trap_code = addr;
		return false;
	}
	//TODO: Check if error return from read_at.(on previous version of r2 this call always return len)
	(void)iob->read_at (io, addr, buf, len);
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, read_at return true/false can't be used to check error vs len
	if (!iob->is_valid_offset (io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
	}
	return len;
}

static bool internal_esil_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (esil && esil->anal, false);

	RIOBind *iob = &esil->anal->iob;
	RIO *io = iob->io;
	if (!io || addr == UT64_MAX) {
		return false;
	}

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
	// TODO: Check if read_at fails
	(void)esil->anal->iob.read_at (io, addr, buf, len);
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, read_at return true/false can't be used to check error vs len
	if (!esil->anal->iob.is_valid_offset (io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = R_ANAL_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd (esil, esil->cmd_ioer, esil->addr, 0);
		}
	}
	return len;
}


/* register callbacks using this anal module. */
R_API bool r_esil_setup(REsil *esil, RAnal *anal, bool romem, bool stats, bool nonull) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	esil->anal = anal;
	esil->parse_goto_count = anal->esil_goto_limit;
	esil->trap = 0;
	esil->trap_code = 0;
	// esil->user = NULL;
	// esil->debug = 0;
	esil->cb.reg_read = internal_esil_reg_read;
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
	r_esil_mem_ro (esil, romem);
#if USE_NEW_ESIL == 0
	r_esil_stats (esil, NULL, stats);
#endif
	r_esil_setup_ops (esil);

	// Try arch esil init cb first, then anal as fallback
	RArchSession *as = R_UNWRAP3 (anal, arch, session);
	if (as) {
		anal->arch->esil = esil;
		RArchPluginEsilCallback esil_cb = R_UNWRAP3 (as, plugin, esilcb);
		if (esil_cb) {
			return esil_cb (as, R_ARCH_ESIL_ACTION_INIT);
		}
	}
	return true;
}

R_API void r_esil_reset(REsil *esil) {
	R_RETURN_IF_FAIL (esil);
	esil->trap = 0;
	sdb_reset (esil->stats);
}

R_API bool r_esil_use(REsil *esil, const char *name) {
	R_RETURN_VAL_IF_FAIL (esil && name, false);
	RListIter *it;
	REsilPlugin *h;
	if (esil->curplug && !strcmp (name, esil->curplug->meta.name)) {
		return true;
	}
	r_list_foreach (esil->plugins, it, h) {
		if (!h->meta.name || strcmp (h->meta.name, name)) {
			continue;
		}
		esil->curplug = h;
		return true;
	}
	return false;
}
