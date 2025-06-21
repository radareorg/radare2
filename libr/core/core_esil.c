/* radare - LGPL - Copyright 2024 - 2025 - condret */

#define R_LOG_ORIGIN "core.esil"
#include <r_core.h>
#include <r_esil.h>
#include <r_reg.h>
#include <r_io.h>

static bool core_esil_op_todo(REsil *esil) {
	RCore *core = esil->user;
	if (core->esil.cmd_todo) {
		r_core_cmd0 (core, core->esil.cmd_todo);
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
	if (core->esil.cmd_intr) {
		r_core_cmd0 (core, core->esil.cmd_intr);
	}
	return r_esil_fire_interrupt (esil, (ut32)interrupt);
}

static bool core_esil_is_reg (void *core, const char *name) {
	RRegItem *ri = r_reg_get (((RCore *)core)->esil.reg, name, -1);
	if (!ri) {
		return false;
	}
	r_unref (ri);
	return true;
}

static bool core_esil_reg_read (void *core, const char *name, ut64 *val) {
	RRegItem *ri = r_reg_get (((RCore *)core)->esil.reg, name, -1);
	if (!ri) {
		return false;
	}
	*val = r_reg_get_value (((RCore *)core)->esil.reg, ri);
	r_unref (ri);
	return true;
}

static bool core_esil_reg_write (void *core, const char *name, ut64 val) {
	return r_reg_setv (((RCore *)core)->esil.reg, name, val);
}

static ut32 core_esil_reg_size (void *core, const char *name) {
	RRegItem *ri = r_reg_get (((RCore *)core)->esil.reg, name, -1);
	if (!ri) {
		return 0;
	}
	const ut32 size = ri->size;
	r_unref (ri);
	return size;
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

static bool core_esil_mem_read (void *core, ut64 addr, ut8 *buf, int len) {
	if ((UT64_MAX - len + 1) < addr) {
		if (!core_esil_mem_read (core, 0ULL, buf + (UT64_MAX - addr + 1),
			len - (UT64_MAX - addr + 1))) {
			return false;
		}
		len = UT64_MAX - addr + 1;
	}
	RCore *c = core;
	if (!addr && c->esil.cfg & R_CORE_ESIL_NONULL) {
		return false;
	}
	
	if (c->esil.cmd_mdev && c->esil.mdev_range && r_str_range_in (c->esil.mdev_range, addr)) {
		r_core_cmdf (c, "%s %"PFMT64d" 0", c->esil.cmd_mdev, c->esil.old_pc);
		return c->num->value;
	}
	return r_io_read_at (c->io, addr, buf, len);
}

static bool core_esil_mem_write (void *core, ut64 addr, const ut8 *buf, int len) {
	if ((UT64_MAX - len + 1) < addr) {
		if (!core_esil_mem_write (core, 0ULL, buf + (UT64_MAX - addr + 1),
			len - (UT64_MAX - addr + 1))) {
			return false;
		}
		len = UT64_MAX - addr + 1;
	}
	RCore *c = core;
	if (!addr && c->esil.cfg & R_CORE_ESIL_NONULL) {
		return false;
	}
	if (c->esil.cmd_mdev && c->esil.mdev_range && r_str_range_in (c->esil.mdev_range, addr)) {
		r_core_cmdf (c, "%s %"PFMT64d" 1", c->esil.cmd_mdev, c->esil.old_pc);
		return c->num->value;
	}
	if (c->esil.cfg & R_CORE_ESIL_RO) {
		RIORegion region;
		if (!r_io_get_region_at (c->io, &region, addr)) {
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
	return r_io_write_at (c->io, addr, buf, len);
}

static REsilMemInterface core_esil_mem_if = {
	.mem_switch = core_esil_mem_switch,
	.mem_read = core_esil_mem_read,
	.mem_write = core_esil_mem_write
};

static void core_esil_voyeur_trap_revert_reg_write (void *user, const char *name,
	ut64 old, ut64 val) {
	RCoreEsil *cesil = user;
	if (!(cesil->cfg & R_CORE_ESIL_TRAP_REVERT)) {
		return;
	}
	r_strbuf_prependf (&cesil->trap_revert, "0x%"PFMT64x",%s,:=,", old, name);
}

static void core_esil_voyeur_trap_revert_mem_write (void *user, ut64 addr,
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

static void core_esil_stepback_free (void *data) {
	if (data) {
		RCoreEsilStepBack *cesb = data;
		free (cesb->expr);
		free (data);
	}
}

R_API bool r_core_esil_init(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->io, false);
	core->esil = (const RCoreEsil){0};
	core->esil.reg = r_reg_new ();
	if (!core->esil.reg) {
		return false;
	}
	core_esil_reg_if.reg = core;
	core_esil_mem_if.mem = core;
	if (!r_esil_init (&core->esil.esil, 4096, false, 64,
		&core_esil_reg_if, &core_esil_mem_if)) {
		goto init_fail;
	}
	if (!r_esil_set_op (&core->esil.esil, "TODO", core_esil_op_todo, 0, 0,
		R_ESIL_OP_TYPE_UNKNOWN, NULL) || !r_esil_set_op (&core->esil.esil,
		"$", core_esil_op_interrupt, 0, 1, R_ESIL_OP_TYPE_UNKNOWN, NULL)) {
		goto op_fail;
	}
	r_strbuf_init (&core->esil.trap_revert);
	core->esil.esil.user = core;
	core->esil.tr_reg = r_esil_add_voyeur (&core->esil.esil, &core->esil,
		core_esil_voyeur_trap_revert_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	core->esil.tr_mem = r_esil_add_voyeur (&core->esil.esil, &core->esil,
		core_esil_voyeur_trap_revert_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	core->esil.stepback.free = core_esil_stepback_free;
	return true;
op_fail:
	r_esil_fini (&core->esil.esil);
init_fail:
	r_reg_free (core->esil.reg);
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
	core->anal->arch->esil = &core->esil.esil;
	r_arch_esilcb (core->anal->arch, R_ARCH_ESIL_ACTION_INIT);
	core->anal->arch->esil = arch_esil;
	char *rp = core->anal->arch->session->plugin->regs (core->anal->arch->session);
	if (!rp) {
		R_LOG_WARN ("Couldn't set reg profile");
		return;
	}
	r_reg_set_profile_string (core->esil.reg, rp);
	free (rp);
}

R_API void r_core_esil_unload_arch(RCore *core) {
	R_RETURN_IF_FAIL (core && core->anal && core->anal->arch);
	if (!core->anal->arch->session || !core->anal->arch->session->plugin ||
		!core->anal->arch->session->plugin->esilcb) {
		return;
	}
	REsil *arch_esil = core->anal->arch->esil;
	core->anal->arch->esil = &core->esil.esil;
	r_arch_esilcb (core->anal->arch, R_ARCH_ESIL_ACTION_FINI);
	core->anal->arch->esil = arch_esil;
}

R_API bool r_core_esil_run_expr_at(RCore *core, const char *expr, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (expr && core && core->anal && core->anal->arch && core->io && core->esil.reg, false);
	const char *pc_name = r_reg_alias_getname (core->esil.reg, R_REG_ALIAS_PC);
	if (!pc_name) {
		R_LOG_ERROR ("CoreEsil reg profile has no pc register");
		return false;
	}
	ut64 pc;
	if (!r_esil_reg_read_silent (&core->esil.esil, pc_name, &pc, NULL)) {
		R_LOG_ERROR ("Couldn't read from PC register");
		return false;
	}
	if ((core->esil.cfg & R_CORE_ESIL_TRAP_REVERT_CONFIG) || core->esil.max_stepback) {
		core->esil.cfg |= R_CORE_ESIL_TRAP_REVERT;
		r_strbuf_initf (&core->esil.trap_revert,
			"0x%"PFMT64x",%s,:=", pc, pc_name);
	} else {
		core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
	}
	core->esil.old_pc = pc;
	r_esil_reg_write_silent (&core->esil.esil, pc_name, addr);
	if (r_esil_parse (&core->esil.esil, expr)) {
		if (core->esil.cfg & R_CORE_ESIL_TRAP_REVERT) {
			if (core->esil.max_stepback) {
				if (core->esil.max_stepback > r_list_length (&core->esil.stepback)) {
					RCoreEsilStepBack *cesb = R_NEW (RCoreEsilStepBack);
					if (!cesb) {
						R_LOG_WARN ("RCoreEsilStepBack allocation failed");
						r_strbuf_fini (&core->esil.trap_revert);
					} else {
						if (!r_list_push (&core->esil.stepback, cesb)) {
							R_LOG_WARN ("Pushing RCoreEsilStepBack failed");
						} else {
							cesb->expr = r_strbuf_drain_nofree (&core->esil.trap_revert);
							cesb->addr = core->esil.old_pc;
						}
					}
				} else {
					//this is like r_list_pop_head + r_list_push,
					//but without expensive calls to malloc and free
					RListIter *iter = core->esil.stepback.head;
					iter->p->n = NULL;
					core->esil.stepback.head = iter->p;
					iter->p = NULL;
					iter->n = core->esil.stepback.tail;
					core->esil.stepback.tail->p = iter;
					core->esil.stepback.tail = iter;
					RCoreEsilStepBack *cesb = iter->data;
					free (cesb->expr);
					cesb->expr = r_strbuf_drain_nofree (&core->esil.trap_revert);
					cesb->addr = core->esil.old_pc;
				}
			} else {
				r_strbuf_fini (&core->esil.trap_revert);
			}
		}
		return true;
	}
	if (core->esil.cfg & R_CORE_ESIL_TRAP_REVERT) {
		//disable trap_revert voyeurs
		core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		char *expr = r_strbuf_drain_nofree (&core->esil.trap_revert);
		//revert all changes
		r_esil_parse (&core->esil.esil, expr);
		free (expr);
	} else {
		r_esil_reg_write_silent (&core->esil.esil, pc_name, core->esil.old_pc);
	}
	if (core->esil.cmd_trap) {
		r_core_cmd0 (core, core->esil.cmd_trap);
	}
	switch (core->esil.esil.trap_code) {
	case R_ANAL_TRAP_WRITE_ERR:
	case R_ANAL_TRAP_READ_ERR:
		if (core->esil.cmd_ioer) {
			r_core_cmdf (core, "%s %"PFMT64d" 0", core->esil.cmd_ioer,
				core->esil.old_pc);
		}
		break;
	}
	return false;
}

R_API bool r_core_esil_single_step(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->anal && core->anal->arch && core->io && core->esil.reg, false);
	const char *pc_name = r_reg_alias_getname (core->esil.reg, R_REG_ALIAS_PC);
	if (!pc_name) {
		R_LOG_ERROR ("CoreEsil reg profile has no pc register");
		return false;
	}
	ut64 pc;
	if (!r_esil_reg_read_silent (&core->esil.esil, pc_name, &pc, NULL)) {
		R_LOG_ERROR ("Couldn't read from PC register");
		return false;
	}
	ut32 trap_code = R_ANAL_TRAP_UNALIGNED;
	const int align = R_MAX (1, r_arch_info (core->anal->arch, R_ARCH_INFO_CODE_ALIGN));
	if (pc % align) {
		goto trap;
	}
	trap_code = R_ANAL_TRAP_READ_ERR;
	//check if pc is in mapped rx area,
	//or in case io is pa
	//check if pc is within desc and desc is at least readable
	RIORegion region;
	if (!r_io_get_region_at (core->io, &region, pc)) {
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
	if ((core->esil.cfg & R_CORE_ESIL_TRAP_REVERT_CONFIG) || core->esil.max_stepback) {
		core->esil.cfg |= R_CORE_ESIL_TRAP_REVERT;
		r_strbuf_initf (&core->esil.trap_revert,
			"0x%"PFMT64x",%s,:=", pc, pc_name);
	} else {
		core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
	}
	core->esil.old_pc = pc;
	pc += op.size;
	char *expr = r_strbuf_drain_nofree (&op.esil);
	r_esil_reg_write_silent (&core->esil.esil, pc_name, pc);
	r_anal_op_fini (&op);
	if (core->esil.cmd_step) {
		r_core_cmdf (core, "%s %"PFMT64d" 0", core->esil.cmd_step, core->esil.old_pc);
		if (core->num->value) {
			free (expr);
			goto skip;
		}
	}
	const bool suc = r_esil_parse (&core->esil.esil, expr);
	free (expr);
	if (suc) {
skip:
		if (core->esil.cfg & R_CORE_ESIL_TRAP_REVERT) {
			if (core->esil.max_stepback) {
				if (core->esil.max_stepback > r_list_length (&core->esil.stepback)) {
					RCoreEsilStepBack *cesb = R_NEW (RCoreEsilStepBack);
					if (!cesb) {
						R_LOG_WARN ("RCoreEsilStepBack allocation failed");
						r_strbuf_fini (&core->esil.trap_revert);
					} else {
						if (!r_list_push (&core->esil.stepback, cesb)) {
							R_LOG_WARN ("Pushing RCoreEsilStepBack failed");
						} else {
							cesb->expr = r_strbuf_drain_nofree (&core->esil.trap_revert);
							cesb->addr = core->esil.old_pc;
						}
					}
				} else {
					//this is like r_list_pop_head + r_list_push,
					//but without expensive calls to malloc and free
					RListIter *iter = core->esil.stepback.head;
					iter->p->n = NULL;
					core->esil.stepback.head = iter->p;
					iter->p = NULL;
					iter->n = core->esil.stepback.tail;
					core->esil.stepback.tail->p = iter;
					core->esil.stepback.tail = iter;
					RCoreEsilStepBack *cesb = iter->data;
					free (cesb->expr);
					cesb->expr = r_strbuf_drain_nofree (&core->esil.trap_revert);
					cesb->addr = core->esil.old_pc;
				}
			} else {
				r_strbuf_fini (&core->esil.trap_revert);
			}
		}
		if (core->esil.cmd_step_out) {
			r_core_cmdf (core, "%s %"PFMT64d" 0", core->esil.cmd_step_out, core->esil.old_pc);
		}
		return true;
	}
	trap_code = core->esil.esil.trap_code;
	if (core->esil.cfg & R_CORE_ESIL_TRAP_REVERT) {
		//disable trap_revert voyeurs
		core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		char *expr = r_strbuf_drain_nofree (&core->esil.trap_revert);
		//revert all changes
		r_esil_parse (&core->esil.esil, expr);
		free (expr);
		goto trap;
	}
	//restore pc
	r_esil_reg_write_silent (&core->esil.esil, pc_name, core->esil.old_pc);
	goto trap;
op_trap:
	r_anal_op_fini (&op);
trap:
	if (core->esil.cmd_trap) {
		r_core_cmd0 (core, core->esil.cmd_trap);
	}
	switch (trap_code) {
	case R_ANAL_TRAP_WRITE_ERR:
	case R_ANAL_TRAP_READ_ERR:
		if (core->esil.cmd_ioer) {
			r_core_cmdf (core, "%s %"PFMT64d" 0", core->esil.cmd_ioer,
				core->esil.old_pc);
		}
		break;
	}
	return false;
}

R_API void r_core_esil_stepback(RCore *core) {
	R_RETURN_IF_FAIL (core && core->io && core->esil.reg);
	if (!r_list_length (&core->esil.stepback)) {
		//not an error
		return;
	}
	RCoreEsilStepBack *cesb = r_list_pop (&core->esil.stepback);
	core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
	r_esil_parse (&core->esil.esil, cesb->expr);
	core_esil_stepback_free (cesb);
}

R_API void r_core_esil_set_max_stepback(RCore *core, ut32 max_stepback) {
	R_RETURN_IF_FAIL (core && core->esil.stepback.free);
	core->esil.max_stepback = max_stepback;
	while (r_list_length (&core->esil.stepback) > max_stepback) {
		core_esil_stepback_free (r_list_pop_head (&core->esil.stepback));
	}
}

R_API void r_core_esil_fini(RCoreEsil *cesil) {
	R_RETURN_IF_FAIL (cesil);
	r_esil_del_voyeur (&cesil->esil, cesil->tr_reg);
	r_esil_del_voyeur (&cesil->esil, cesil->tr_mem);
	r_esil_fini (&cesil->esil);
	r_strbuf_fini (&cesil->trap_revert);
	if (cesil->reg) {
		r_reg_free (cesil->reg);
		cesil->reg = NULL;
	}
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
