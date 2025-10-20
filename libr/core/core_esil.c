/* radare - LGPL - Copyright 2024-2025 - condret */

#define R_LOG_ORIGIN "core.esil"
#include <r_core.h>
#include <r_esil.h>
#include <r_reg.h>
#include <r_io.h>

static bool core_esil_op_todo(REsil *esil) {
	RCore *core = esil->user;
	if (R_STR_ISNOTEMPTY (core->cesil.cmd_todo)) {
		r_core_cmd0 (core, core->cesil.cmd_todo);
	}
	return true;
}

static bool core_esil_op_interrupt(REsil *esil) {
	char *str = r_esil_pop (esil);
	ut64 interrupt;
	if (!r_esil_get_parm (esil, str, &interrupt)) {
		free (str);
		return false;
	}
	free (str);
	RCore *core = esil->user;
	if (R_STR_ISNOTEMPTY (core->cesil.cmd_intr)) {
		r_core_cmd0 (core, core->cesil.cmd_intr);
	}
	return r_esil_fire_interrupt (esil, (ut32)interrupt);
}

static bool core_esil_is_reg(void *_core, const char *name) {
	RCore *core = _core;
	RRegItem *ri = r_reg_get (core->anal->reg, name, -1);
	if (!ri) {
		return false;
	}
	r_unref (ri);
	return true;
}

static bool core_esil_reg_read(void *_core, const char *name, ut64 *val) {
	RCore *core = _core;
	RRegItem *ri = r_reg_get (core->anal->reg, name, -1);
	if (R_LIKELY (ri)) {
		*val = r_reg_get_value (core->anal->reg, ri);
		r_unref (ri);
		return true;
	}
	return false;
}

static bool core_esil_reg_write (void *_core, const char *name, ut64 val) {
	RCore *core = _core;
	return r_reg_setv (core->cesil.reg, name, val);
}

static ut32 core_esil_reg_size(void *_core, const char *name) {
	RCore *core = _core;
	RRegItem *ri = r_reg_get (core->anal->reg, name, -1);
	if (R_LIKELY (ri)) {
		const ut32 size = ri->size;
		r_unref (ri);
		return size;
	}
	return 0;
}

static REsilRegInterface core_esil_reg_if = {
	.is_reg = core_esil_is_reg,
	.reg_read = core_esil_reg_read,
	.reg_write = core_esil_reg_write,
	.reg_size = core_esil_reg_size
};

static bool core_esil_mem_switch (void *core, ut32 idx) {
	return r_io_bank_use (((RCore *)core)->io, idx);
}

static bool core_esil_mem_read (void *_core, ut64 addr, ut8 *buf, int len) {
	if ((UT64_MAX - len + 1) < addr) {
		if (!core_esil_mem_read (_core, 0ULL, buf + (UT64_MAX - addr + 1),
			len - (UT64_MAX - addr + 1))) {
			return false;
		}
		len = UT64_MAX - addr + 1;
	}
	RCore *core = _core;
	if (!addr && core->cesil.cfg & R_CORE_ESIL_NONULL) {
		return false;
	}
	if (R_STR_ISNOTEMPTY (core->cesil.cmd_mdev) && core->cesil.mdev_range && r_str_range_in (core->cesil.mdev_range, addr)) {
		r_core_cmdf (core, "%s %"PFMT64d" 0", core->cesil.cmd_mdev, core->cesil.old_pc);
		return core->num->value;
	}
	return r_io_read_at (core->io, addr, buf, len);
}

static bool core_esil_mem_write (void *_core, ut64 addr, const ut8 *buf, int len) {
	RCore *core = _core;
	if ((UT64_MAX - len + 1) < addr) {
		if (!core_esil_mem_write (core, 0ULL, buf + (UT64_MAX - addr + 1),
			len - (UT64_MAX - addr + 1))) {
			return false;
		}
		len = UT64_MAX - addr + 1;
	}
	if (!addr && core->cesil.cfg & R_CORE_ESIL_NONULL) {
		return false;
	}
	if (R_STR_ISNOTEMPTY (core->cesil.cmd_mdev) && core->cesil.mdev_range && r_str_range_in (core->cesil.mdev_range, addr)) {
		r_core_cmdf (core, "%s %"PFMT64d" 1", core->cesil.cmd_mdev, core->cesil.old_pc);
		return core->num->value;
	}
	if (core->cesil.cfg & R_CORE_ESIL_RO) {
		RIORegion region;
		if (!r_io_get_region_at (core->io, &region, addr)) {
			//maybe check voidwrites config here
			return true;
		}
		if (!(region.perm & R_PERM_W)) {
			return false;
		}
		if (r_itv_contain (region.itv, addr + len - 1)) {
			return true;
		}
		return core_esil_mem_write (core, r_itv_end (region.itv),
			NULL, addr + len - r_itv_end (region.itv));	//no need to pass buf, because this is RO mode
	}
	return r_io_write_at (core->io, addr, buf, len);
}

static REsilMemInterface core_esil_mem_if = {
	.mem_switch = core_esil_mem_switch,
	.mem_read = core_esil_mem_read,
	.mem_write = core_esil_mem_write
};

static void core_esil_voyeur_trap_revert_reg_write(void *user, const char *name, ut64 old, ut64 val) {
	RCoreEsil *cesil = user;
	if (!(cesil->cfg & R_CORE_ESIL_TRAP_REVERT)) {
		return;
	}
	r_strbuf_prependf (&cesil->trap_revert, "0x%"PFMT64x",%s,:=,", old, name);
}

static void core_esil_voyeur_trap_revert_mem_write(void *user, ut64 addr,
	const ut8 *old, const ut8 *buf, int len) {
	RCoreEsil *cesil = user;
	if (!(cesil->cfg & R_CORE_ESIL_TRAP_REVERT)) {
		return;
	}
	if (cesil->cfg & R_CORE_ESIL_RO) {
		return;
	}
	int i;
	for (i = 0; i < len; i++) {
		//TODO: optimize this after breaking
		r_strbuf_prependf (&cesil->trap_revert,
			"0x%02x,0x%"PFMT64x",=[1],", old[i], addr + i);
	}
}

static void core_esil_stepback_free(void *data) {
	if (data) {
		RCoreEsilStepBack *cesb = data;
		free (cesb->expr);
		free (data);
	}
}

R_API bool r_core_esil_init(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->io, false);
	core->cesil = (const RCoreEsil){0};
#if 0 // hack
	core->cesil.reg = core->anal->reg;
#else
	core->cesil.reg = r_reg_new ();
	if (!core->cesil.reg) {
		return false;
	}
#endif
	core_esil_reg_if.reg = core;
	core_esil_mem_if.mem = core;
	if (!r_esil_init (&core->cesil.esil, 4096, false, 64,
		&core_esil_reg_if, &core_esil_mem_if)) {
		goto init_fail;
	}
	if (!r_esil_set_op (&core->cesil.esil, "TODO", core_esil_op_todo, 0, 0,
		R_ESIL_OP_TYPE_UNKNOWN, NULL) || !r_esil_set_op (&core->cesil.esil,
		"$", core_esil_op_interrupt, 0, 1, R_ESIL_OP_TYPE_UNKNOWN, NULL)) {
		goto op_fail;
	}
	r_strbuf_init (&core->cesil.trap_revert);
	core->cesil.esil.user = core;
	core->cesil.tr_reg = r_esil_add_voyeur (&core->cesil.esil, &core->cesil,
		core_esil_voyeur_trap_revert_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	core->cesil.tr_mem = r_esil_add_voyeur (&core->cesil.esil, &core->cesil,
		core_esil_voyeur_trap_revert_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	core->cesil.stepback.free = core_esil_stepback_free;
	return true;
op_fail:
	r_esil_fini (&core->cesil.esil);
init_fail:
	r_reg_free (core->cesil.reg);
	return false;
}

R_API void r_core_esil_load_arch(RCore *core) {
	R_RETURN_IF_FAIL (core && core->anal && core->anal->arch);
	if (!core->anal->arch->session || !core->anal->arch->session->plugin ||
		!core->anal->arch->session->plugin->esilcb ||
		!core->anal->arch->session->plugin->regs) {
		//This doesn't count as fail
		return;
	}
	//This is awful. TODO: massage r_arch api
	REsil *arch_esil = core->anal->arch->esil;
	core->anal->arch->esil = &core->cesil.esil;
	r_arch_esilcb (core->anal->arch, R_ARCH_ESIL_ACTION_INIT);
	core->anal->arch->esil = arch_esil;
	char *rp = core->anal->arch->session->plugin->regs (core->anal->arch->session);
	if (!rp) {
		R_LOG_WARN ("Couldn't set reg profile");
		return;
	}
	r_reg_set_profile_string (core->cesil.reg, rp);
	free (rp);
}

R_API void r_core_esil_unload_arch(RCore *core) {
	R_RETURN_IF_FAIL (core && core->anal && core->anal->arch);
	if (!core->anal->arch->session || !core->anal->arch->session->plugin ||
		!core->anal->arch->session->plugin->esilcb) {
		return;
	}
	REsil *arch_esil = core->anal->arch->esil;
	core->anal->arch->esil = &core->cesil.esil;
	r_arch_esilcb (core->anal->arch, R_ARCH_ESIL_ACTION_FINI);
	core->anal->arch->esil = arch_esil;
}

R_API bool r_core_esil_run_expr_at(RCore *core, const char *expr, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (expr && core && core->anal && core->anal->arch && core->io && core->cesil.reg, false);
	const char *pc_name = r_reg_alias_getname (core->cesil.reg, R_REG_ALIAS_PC);
	if (!pc_name) {
		R_LOG_ERROR ("CoreEsil reg profile has no pc register");
		return false;
	}
	ut64 pc;
	if (!r_esil_reg_read_silent (&core->cesil.esil, pc_name, &pc, NULL)) {
		R_LOG_ERROR ("Couldn't read from PC register");
		return false;
	}
	if ((core->cesil.cfg & R_CORE_ESIL_TRAP_REVERT_CONFIG) || core->cesil.max_stepback) {
		core->cesil.cfg |= R_CORE_ESIL_TRAP_REVERT;
		r_strbuf_initf (&core->cesil.trap_revert,
			"0x%"PFMT64x",%s,:=", pc, pc_name);
	} else {
		core->cesil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
	}
	core->cesil.old_pc = pc;
	r_esil_reg_write_silent (&core->cesil.esil, pc_name, addr);
	if (r_esil_parse (&core->cesil.esil, expr)) {
		if (core->cesil.cfg & R_CORE_ESIL_TRAP_REVERT) {
			if (core->cesil.max_stepback) {
				if (core->cesil.max_stepback > r_list_length (&core->cesil.stepback)) {
					RCoreEsilStepBack *cesb = R_NEW (RCoreEsilStepBack);
					if (!cesb) {
						R_LOG_WARN ("RCoreEsilStepBack allocation failed");
						r_strbuf_fini (&core->cesil.trap_revert);
					} else {
						if (!r_list_push (&core->cesil.stepback, cesb)) {
							R_LOG_WARN ("Pushing RCoreEsilStepBack failed");
						} else {
							cesb->expr = r_strbuf_drain_nofree (&core->cesil.trap_revert);
							cesb->addr = core->cesil.old_pc;
						}
					}
				} else {
					//this is like r_list_pop_head + r_list_push,
					//but without expensive calls to malloc and free
					RListIter *iter = core->cesil.stepback.head;
					iter->p->n = NULL;
					core->cesil.stepback.head = iter->p;
					iter->p = NULL;
					iter->n = core->cesil.stepback.tail;
					core->cesil.stepback.tail->p = iter;
					core->cesil.stepback.tail = iter;
					RCoreEsilStepBack *cesb = iter->data;
					free (cesb->expr);
					cesb->expr = r_strbuf_drain_nofree (&core->cesil.trap_revert);
					cesb->addr = core->cesil.old_pc;
				}
			} else {
				r_strbuf_fini (&core->cesil.trap_revert);
			}
		}
		return true;
	}
	if (core->cesil.cfg & R_CORE_ESIL_TRAP_REVERT) {
		//disable trap_revert voyeurs
		core->cesil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		char *expr = r_strbuf_drain_nofree (&core->cesil.trap_revert);
		//revert all changes
		r_esil_parse (&core->cesil.esil, expr);
		free (expr);
	} else {
		r_esil_reg_write_silent (&core->cesil.esil, pc_name, core->cesil.old_pc);
	}
	if (R_STR_ISNOTEMPTY (core->cesil.cmd_trap)) {
		r_core_cmd0 (core, core->cesil.cmd_trap);
	}
	switch (core->cesil.esil.trap_code) {
	case R_ANAL_TRAP_WRITE_ERR:
	case R_ANAL_TRAP_READ_ERR:
		if (R_STR_ISNOTEMPTY (core->cesil.cmd_ioer)) {
			r_core_cmdf (core, "%s %"PFMT64d" 0", core->cesil.cmd_ioer,
				core->cesil.old_pc);
		}
		break;
	}
	return false;
}

R_API bool r_core_esil_single_step(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->anal && core->anal->arch && core->io && core->cesil.reg, false);
	RReg *reg = core->anal->reg; // core->cesil.reg NO
	const char *pc_name = r_reg_alias_getname (reg, R_REG_ALIAS_PC);
	if (!pc_name) {
		R_LOG_ERROR ("CoreEsil reg profile has no pc register");
		return false;
	}
	ut64 pc;
	if (!r_esil_reg_read_silent (&core->cesil.esil, pc_name, &pc, NULL)) {
		R_LOG_ERROR ("Couldn't read from PC register");
		return false;
	}
	ut32 trap_code = R_ANAL_TRAP_UNALIGNED;
	const int align = R_MAX (1, r_arch_info (core->anal->arch, R_ARCH_INFO_CODE_ALIGN));
	if (pc % align) {
		R_LOG_ERROR ("Unaligned execution at PC=0x%08"PFMT64x, pc);
		goto trap;
	}
	trap_code = R_ANAL_TRAP_READ_ERR;
	//check if pc is in mapped rx area,
	//or in case io is pa
	//check if pc is within desc and desc is at least readable
	RIORegion region;
	if (!r_io_get_region_at (core->io, &region, pc)) {
		R_LOG_ERROR ("pc not in region %s = 0x%"PFMT64x, pc_name, pc);
		goto trap;
	}
	if ((region.perm & (R_PERM_R | R_PERM_X)) != (R_PERM_R | R_PERM_X) ||
		(!core->io->va && !(region.perm & R_PERM_R))) {
		goto trap;
	}
	trap_code = R_ANAL_TRAP_NONE;
	int max_opsize = R_MIN (64,
		r_arch_info (core->anal->arch, R_ARCH_INFO_MAXOP_SIZE));
	if (R_UNLIKELY (max_opsize < 1)) {
		R_LOG_WARN ("Couldn't fetch max_opsize from archplugin. Using 32");
		max_opsize = 32;
	}
	ut8 buf[64];
	if (R_UNLIKELY (!r_io_read_at (core->io, pc, buf, max_opsize))) {
		R_LOG_ERROR ("Couldn't read data to decode from 0x%"PFMT64x, pc);
		return false;
	}
	RAnalOp op;
	r_anal_op_init (&op);
	//cannot fail, because max size here is 64
	r_anal_op_set_bytes (&op, pc, buf, max_opsize);
	//intentionally not using r_anal_op here, because this function is a fucking fever dream
	if (!r_arch_decode (core->anal->arch, &op,
		R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL)) {
		R_LOG_ERROR ("COuldn't decode instruction at 0x%"PFMT64x, pc);
		r_anal_op_fini (&op);
		return false;
	}
	RAnalHint *hint = r_anal_hint_get (core->anal, pc);
	if (hint) {
		if (hint->size) {
			op.size = hint->size;
		}
		if (hint->type > 0) {
			op.type = hint->type;
		}
		if (hint->esil) {
			r_strbuf_set (&op.esil, hint->esil);
		}
		//maybe do something about arch, bits and endian shit here
		//difficult, because that could mean a different reg profile,
		//which would invalidate some previous steps
		r_anal_hint_free (hint);
		hint = NULL;
	}
	if (op.size < 1 || op.type == R_ANAL_OP_TYPE_ILL ||
		op.type == R_ANAL_OP_TYPE_UNK) {
		goto op_trap;
	}
	if (!r_itv_contain (region.itv, pc + op.size)) {
		goto op_trap;
	}
	if ((core->cesil.cfg & R_CORE_ESIL_TRAP_REVERT_CONFIG) || core->cesil.max_stepback) {
		core->cesil.cfg |= R_CORE_ESIL_TRAP_REVERT;
		r_strbuf_initf (&core->cesil.trap_revert,
			"0x%"PFMT64x",%s,:=", pc, pc_name);
	} else {
		core->cesil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
	}
	core->cesil.old_pc = pc;
	pc += op.size;
	char *expr = r_strbuf_drain_nofree (&op.esil);
	r_esil_reg_write_silent (&core->cesil.esil, pc_name, pc);
	r_reg_setv (core->anal->reg, pc_name, pc); // XXX
	r_anal_op_fini (&op);
	if (R_STR_ISNOTEMPTY (core->cesil.cmd_step)) {
		r_core_cmdf (core, "%s %"PFMT64d" 0", core->cesil.cmd_step, core->cesil.old_pc);
		if (core->num->value) {
			free (expr);
			goto skip;
		}
	}
	if (R_STR_ISEMPTY (expr)) {
		// nops, endbrp ,..
		goto skip;
	}
	const bool suc = r_esil_parse (core->anal->esil, expr);
	//const bool suc = r_esil_parse (&core->cesil.esil, expr);
	free (expr);
	if (suc) {
skip:
		if (core->cesil.cfg & R_CORE_ESIL_TRAP_REVERT) {
			if (core->cesil.max_stepback) {
				if (core->cesil.max_stepback > r_list_length (&core->cesil.stepback)) {
					RCoreEsilStepBack *cesb = R_NEW0 (RCoreEsilStepBack);
					if (!cesb) {
						R_LOG_WARN ("RCoreEsilStepBack allocation failed");
						r_strbuf_fini (&core->cesil.trap_revert);
					} else {
						if (!r_list_push (&core->cesil.stepback, cesb)) {
							R_LOG_WARN ("Pushing RCoreEsilStepBack failed");
						} else {
							cesb->expr = r_strbuf_drain_nofree (&core->cesil.trap_revert);
							cesb->addr = core->cesil.old_pc;
						}
					}
				} else {
					//this is like r_list_pop_head + r_list_push,
					//but without expensive calls to malloc and free
					RListIter *iter = core->cesil.stepback.head;
					if (iter->p) {
						iter->p->n = NULL;
					} else {
						R_LOG_ERROR ("iter->p shouldnt be null");
					}
					core->cesil.stepback.head = iter->p;
					iter->p = NULL;
					iter->n = core->cesil.stepback.tail;
					core->cesil.stepback.tail->p = iter;
					core->cesil.stepback.tail = iter;
					RCoreEsilStepBack *cesb = iter->data;
					free (cesb->expr);
					cesb->expr = r_strbuf_drain_nofree (&core->cesil.trap_revert);
					cesb->addr = core->cesil.old_pc;
				}
			} else {
				r_strbuf_fini (&core->cesil.trap_revert);
			}
		}
		if (R_STR_ISNOTEMPTY (core->cesil.cmd_step_out)) {
			r_core_cmdf (core, "%s %"PFMT64d" 0", core->cesil.cmd_step_out, core->cesil.old_pc);
		}
		return true;
	}
	trap_code = core->cesil.esil.trap_code;
	if (core->cesil.cfg & R_CORE_ESIL_TRAP_REVERT) {
		//disable trap_revert voyeurs
		core->cesil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		char *expr = r_strbuf_drain_nofree (&core->cesil.trap_revert);
		//revert all changes
		// r_esil_parse (&core->cesil.esil, expr);
		r_esil_parse (core->anal->esil, expr);
		free (expr);
		goto trap;
	}
	//restore pc
	// eprintf ("PC WRITE %llx\n", core->cesil.old_pc);
	r_esil_reg_write_silent (&core->cesil.esil, pc_name, core->cesil.old_pc);
	goto trap;
op_trap:
	r_anal_op_fini (&op);
trap:
	if (R_STR_ISNOTEMPTY (core->cesil.cmd_trap)) {
		r_core_cmd0 (core, core->cesil.cmd_trap);
	}
	switch (trap_code) {
	case R_ANAL_TRAP_WRITE_ERR:
	case R_ANAL_TRAP_READ_ERR:
		if (R_STR_ISNOTEMPTY (core->cesil.cmd_ioer)) {
			r_core_cmdf (core, "%s %"PFMT64d" 0", core->cesil.cmd_ioer,
				core->cesil.old_pc);
		}
		break;
	}
	return false;
}

R_API void r_core_esil_stepback(RCore *core) {
	R_RETURN_IF_FAIL (core && core->io && core->cesil.reg);
	if (!r_list_length (&core->cesil.stepback)) {
		//not an error
		return;
	}
	RCoreEsilStepBack *cesb = r_list_pop (&core->cesil.stepback);
	core->cesil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
	r_esil_parse (&core->cesil.esil, cesb->expr);
	core_esil_stepback_free (cesb);
}

R_API void r_core_esil_set_max_stepback(RCore *core, ut32 max_stepback) {
	R_RETURN_IF_FAIL (core && core->cesil.stepback.free);
	core->cesil.max_stepback = max_stepback;
	while (r_list_length (&core->cesil.stepback) > max_stepback) {
		core_esil_stepback_free (r_list_pop_head (&core->cesil.stepback));
	}
}

R_API void r_core_esil_fini(RCoreEsil *cesil) {
	R_RETURN_IF_FAIL (cesil);
	r_esil_del_voyeur (&cesil->esil, cesil->tr_reg);
	r_esil_del_voyeur (&cesil->esil, cesil->tr_mem);
	r_esil_fini (&cesil->esil);
	r_strbuf_fini (&cesil->trap_revert);
#if 1
	if (cesil->reg) {
		r_reg_free (cesil->reg);
		cesil->reg = NULL;
	}
#endif
	R_FREE (cesil->cmd_step);
	R_FREE (cesil->cmd_step_out);
	R_FREE (cesil->cmd_intr);
	R_FREE (cesil->cmd_trap);
	R_FREE (cesil->cmd_mdev);
	R_FREE (cesil->cmd_todo);
	R_FREE (cesil->cmd_ioer);
	R_FREE (cesil->mdev_range);
	r_list_purge (&cesil->stepback);
	cesil->esil = (const REsil){0};
}
