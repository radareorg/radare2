/* radare - LGPL - Copyright 2024-2026 - condret */

#define R_LOG_ORIGIN "core.esil"
#include <r_core.h>
#include <r_esil.h>
#include <r_reg.h>
#include <r_io.h>

// R2R db/esil/riscv_32

static bool core_esil_op_todo(REsil *esil) {
	RCore *core = esil->user;
	if (R_STR_ISNOTEMPTY (core->esil.cmds.todo)) {
		r_core_cmdf (core, "%s %" PFMT64d " 0", core->esil.cmds.todo, esil->addr);
	}
	return true;
}

static bool core_esil_op_interrupt(REsil *esil) {
	const RStrs str = r_esil_pop (esil);
	ut64 interrupt;
	if (!r_esil_get_parm (esil, str, &interrupt)) {
		return false;
	}
	RCore *core = esil->user;
	if (R_STR_ISNOTEMPTY (core->esil.cmds.intr)) {
		r_core_cmdf (core, "%s %" PFMT64d " 0", core->esil.cmds.intr, interrupt);
	}
	return r_esil_fire_interrupt (esil, (ut32)interrupt);
}

static bool core_esil_cmd(RCore *core, const char *cmd, ut64 a1, ut64 a2) {
	if (R_STR_ISEMPTY (cmd)) {
		return false;
	}
	r_core_cmdf (core, "%s %" PFMT64d " %" PFMT64d, cmd, a1, a2);
	return core->num->value;
}

static bool core_esil_mem_is_valid(RCore *core, ut64 addr, bool write) {
	const bool valid = r_io_is_valid_offset (core->io, addr, write? R_PERM_W: R_PERM_R);
	if (!valid && R_STR_ISNOTEMPTY (core->esil.cmds.ioer)) {
		core_esil_cmd (core, core->esil.cmds.ioer, core->esil.sb.old_pc, write);
	}
	return valid;
}

static bool core_esil_trap_revert_start(RCore *core, const char *pc_name, ut64 pc) {
	RCoreEsil *ce = &core->esil;
	if (ce->cfg & R_CORE_ESIL_TRAP_REVERT) {
		return false;
	}
	ce->sb.old_pc = pc;
	if (!(ce->cfg & R_CORE_ESIL_TRAP_REVERT_CONFIG) && !ce->sb.max) {
		return false;
	}
	ce->cfg |= R_CORE_ESIL_TRAP_REVERT;
	r_strbuf_initf (&ce->sb.revert, "0x%" PFMT64x ",%s,:=", pc, pc_name);
	return true;
}

// XXX transitional: the core esil VM operates on the shared anal reg until a
// sync mechanism between the isolated core->esil.reg and the anal/dbg regs lands
static RReg *core_esil_reg(void *core) {
	return ((RCore *)core)->anal->reg;
}

static bool core_esil_is_reg(void *core, const char *name) {
	RRegItem *ri = r_reg_get (core_esil_reg (core), name, -1);
	if (!ri) {
		return false;
	}
	r_unref (ri);
	return true;
}

static bool core_esil_reg_read(void *core, const char *name, ut64 *val) {
	RReg *reg = core_esil_reg (core);
	RRegItem *ri = r_reg_get (reg, name, -1);
	if (!ri) {
		return false;
	}
	*val = r_reg_get_value (reg, ri);
	r_unref (ri);
	return true;
}

static bool core_esil_reg_write(void *core, const char *name, ut64 val) {
	return r_reg_setv (core_esil_reg (core), name, val);
}

static ut32 core_esil_reg_size(void *core, const char *name) {
	RRegItem *ri = r_reg_get (core_esil_reg (core), name, -1);
	if (!ri) {
		return 0;
	}
	const ut32 size = ri->size;
	r_unref (ri);
	return size;
}

static ut32 core_esil_reg_packed_size(void *core, const char *name) {
	RRegItem *ri = r_reg_get (core_esil_reg (core), name, -1);
	if (!ri) {
		return 0;
	}
	const ut32 psize = ri->packed_size > 0? (ut32)ri->packed_size: 0;
	r_unref (ri);
	return psize;
}

static bool core_esil_reg_alias(void *core, int alias, const char *name) {
	return r_reg_alias_setname (core_esil_reg (core), alias, name);
}

static bool core_esil_mem_switch(void *core, ut32 idx) {
	return r_io_bank_use (((RCore *)core)->io, idx);
}

static bool core_esil_mem_read(void *core, ut64 addr, ut8 *buf, int len) {
	if ((UT64_MAX - len + 1) < addr) {
		if (!core_esil_mem_read (core, 0ULL, buf + (UT64_MAX - addr + 1), len - (UT64_MAX - addr + 1))) {
			return false;
		}
		len = UT64_MAX - addr + 1;
	}
	RCore *c = core;
	if (!addr && c->esil.cfg & R_CORE_ESIL_NONULL) {
		return false;
	}

	const REsilCmds *cmds = &c->esil.cmds;
	if (R_STR_ISNOTEMPTY (cmds->mdev) && cmds->mdev_range &&
		r_str_range_in (cmds->mdev_range, addr)) {
		return core_esil_cmd (c, cmds->mdev, c->esil.sb.old_pc, 0);
	}
	const bool ret = r_io_read_at (c->io, addr, buf, len);
	const bool valid = core_esil_mem_is_valid (c, addr, false);
	return ret && valid;
}

static bool core_esil_mem_write(void *core, ut64 addr, const ut8 *buf, int len) {
	if ((UT64_MAX - len + 1) < addr) {
		if (!core_esil_mem_write (core, 0ULL, buf + (UT64_MAX - addr + 1), len - (UT64_MAX - addr + 1))) {
			return false;
		}
		len = UT64_MAX - addr + 1;
	}
	RCore *c = core;
	if (!addr && c->esil.cfg & R_CORE_ESIL_NONULL) {
		return false;
	}
	const REsilCmds *cmds = &c->esil.cmds;
	if (R_STR_ISNOTEMPTY (cmds->mdev) && cmds->mdev_range &&
		r_str_range_in (cmds->mdev_range, addr)) {
		return core_esil_cmd (c, cmds->mdev, c->esil.sb.old_pc, 1);
	}
	if (c->esil.cfg & R_CORE_ESIL_RO) {
		RIORegion region;
		if (!r_io_get_region_at (c->io, &region, addr)) {
			// maybe check voidwrites config here
			return true;
		}
		if (! (region.perm & R_PERM_W)) {
			return false;
		}
		if (r_itv_contain (region.itv, addr + len - 1)) {
			return true;
		}
		return core_esil_mem_write (core, r_itv_end (region.itv), NULL, addr + len - r_itv_end (region.itv)); // no need to pass buf, because this is RO mode
	}
	const bool ret = r_io_write_at (c->io, addr, buf, len);
	const bool valid = core_esil_mem_is_valid (c, addr, true);
	return ret && valid;
}

static bool core_esil_set_bits(void *core, int bits) {
	r_config_set_i (((RCore *)core)->config, "asm.bits", bits);
	return true;
}

static void core_esil_voyeur_trap_revert_reg_write(void *user, const char *name, ut64 old, ut64 val) {
	RCoreEsil *cesil = user;
	if (! (cesil->cfg & R_CORE_ESIL_TRAP_REVERT)) {
		return;
	}
	r_strbuf_prependf (&cesil->sb.revert, "0x%" PFMT64x ",%s,:=,", old, name);
}

static void core_esil_voyeur_trap_revert_mem_write(void *user, ut64 addr, const ut8 *old, const ut8 *buf, int len) {
	RCoreEsil *cesil = user;
	if (! (cesil->cfg & R_CORE_ESIL_TRAP_REVERT)) {
		return;
	}
	if (cesil->cfg & R_CORE_ESIL_RO) {
		return;
	}
	int i;
	for (i = 0; i < len; i++) {
		// TODO: optimize this after breaking
		r_strbuf_prependf (&cesil->sb.revert,
			"0x%02x,0x%" PFMT64x ",=[1],",
			old[i],
			addr + i);
	}
}

static void core_esil_voyeur_trap_revert_set_bits(void *user, int bits) {
	RCore *core = user;
	RCoreEsil *cesil = &core->esil;
	if (! (cesil->cfg & R_CORE_ESIL_TRAP_REVERT)) {
		return;
	}
	ut32 old_bits = r_config_get_i (core->config, "asm.bits");
	r_strbuf_prependf (&cesil->sb.revert, "%d,BITS,", old_bits);
}

static void core_esil_voyeur_trap_revert_reg_alias(void *user, int alias, const char *name) {
	RCore *core = user;
	RCoreEsil *cesil = &core->esil;
	if (! (cesil->cfg & R_CORE_ESIL_TRAP_REVERT)) {
		return;
	}
	const char *old_name = r_reg_alias_getname (core_esil_reg (core), alias);
	const char *alias_name = r_reg_alias_tostring (alias);
	if (!old_name || !alias_name) {
		return;
	}
	r_strbuf_prependf (&cesil->sb.revert, "%s,%s,r=,", old_name, alias_name);
}

static void core_esil_stepback_free(void *data) {
	if (data) {
		RCoreEsilStepBack *cesb = data;
		free (cesb->expr);
		free (data);
	}
}

static void core_esil_cmds_fini(REsilCmds *cmds) {
	R_FREE (cmds->step);
	R_FREE (cmds->step_out);
	R_FREE (cmds->intr);
	R_FREE (cmds->trap);
	R_FREE (cmds->mdev);
	R_FREE (cmds->todo);
	R_FREE (cmds->ioer);
	R_FREE (cmds->mdev_range);
}

static void core_esil_stepback_fini(REsil *esil, REsilStepback *sb) {
	r_esil_del_voyeur (esil, sb->v_reg);
	r_esil_del_voyeur (esil, sb->v_mem);
	r_esil_del_voyeur (esil, sb->v_bits);
	r_esil_del_voyeur (esil, sb->v_alias);
	r_strbuf_fini (&sb->revert);
	r_list_purge (&sb->list);
}

static void core_esil_record_stepback(RCore *core) {
	RCoreEsil *cesil = &core->esil;
	REsilStepback *sb = &cesil->sb;
	if (!sb->max) {
		r_strbuf_fini (&sb->revert);
		return;
	}
	RCoreEsilStepBack *cesb = NULL;
	if (sb->max > r_list_length (&sb->list)) {
		cesb = R_NEW (RCoreEsilStepBack);
		if (!cesb) {
			R_LOG_WARN ("RCoreEsilStepBack allocation failed");
			r_strbuf_fini (&sb->revert);
			return;
		}
		if (!r_list_push (&sb->list, cesb)) {
			R_LOG_WARN ("Pushing RCoreEsilStepBack failed");
			free (cesb);
			r_strbuf_fini (&sb->revert);
			return;
		}
	} else {
		RListIter *iter = sb->list.head;
		if (!iter) {
			r_strbuf_fini (&sb->revert);
			return;
		}
		if (iter != sb->list.tail) {
			sb->list.head = iter->n;
			sb->list.head->p = NULL;
			iter->n = NULL;
			iter->p = sb->list.tail;
			sb->list.tail->n = iter;
			sb->list.tail = iter;
		}
		cesb = iter->data;
		free (cesb->expr);
	}
	cesb->expr = r_strbuf_drain_nofree (&sb->revert);
	cesb->addr = sb->old_pc;
}

static bool core_esil_step_delay_slot(RCore *core, RArchSession *as, const char *pc_name, ut64 ds_addr, int max_opsize) {
	REsil *esil = &core->esil.esil;
	ut64 pc_after_op = 0;
	if (!r_esil_reg_read_silent (esil, pc_name, &pc_after_op, NULL)) {
		return false;
	}
	const char *arch = r_config_get (core->config, "asm.arch");
	const bool is_mips = r_str_startswith (arch, "mips");
	const bool is_sh = r_str_startswith (arch, "sh");
	if ((is_mips && pc_after_op == ds_addr + 4) || (is_sh && pc_after_op == ds_addr)) {
		esil->delay = 0;
		return true;
	}
	ut64 saved_pc = UT64_MAX;
	if (!esil->jump_target_set && pc_after_op != ds_addr) {
		saved_pc = pc_after_op;
	}
	ut8 buf[64];
	(void)r_io_read_at (core->io, ds_addr, buf, max_opsize);
	RAnalOp op;
	r_anal_op_init (&op);
	r_anal_op_set_bytes (&op, ds_addr, buf, max_opsize);
	if (!r_arch_session_decode (as, &op, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT)) {
		r_anal_op_fini (&op);
		if (esil->jump_target_set && esil->delay) {
			r_esil_set_pc (esil, esil->jump_target);
			esil->jump_target_set = 0;
			esil->delay = 0;
		} else if (saved_pc != UT64_MAX) {
			r_esil_reg_write_silent (esil, pc_name, saved_pc);
			esil->delay = 0;
		}
		return true;
	}
	r_esil_reg_write_silent (esil, pc_name, ds_addr);
	char *expr = r_strbuf_drain_nofree (&op.esil);
	if (R_STR_ISNOTEMPTY (expr)) {
		esil->addr = ds_addr;
		(void)r_esil_parse (esil, expr);
		esil->trap = false;
	}
	free (expr);
	ut64 pc_ds = 0;
	(void)r_esil_reg_read_silent (esil, pc_name, &pc_ds, NULL);
	if (pc_ds == ds_addr) {
		r_esil_reg_write_silent (esil, pc_name, ds_addr + op.size);
		pc_ds = ds_addr + op.size;
	}
	if (saved_pc != UT64_MAX && !esil->jump_target_set &&
		(pc_ds == ds_addr || pc_ds == ds_addr + op.size)) {
		r_esil_reg_write_silent (esil, pc_name, saved_pc);
	}
	r_anal_op_fini (&op);
	return true;
}

static void core_esil_align_pc(RCore *core, const char *pc_name) {
	RArchConfig *cfg = R_UNWRAP3 (core, anal, config);
	if (!cfg || cfg->codealign < 1) {
		return;
	}
	ut64 pc = 0;
	if (r_esil_reg_read_silent (&core->esil.esil, pc_name, &pc, NULL)) {
		r_esil_reg_write_silent (&core->esil.esil, pc_name, pc - (pc % cfg->codealign));
	}
}

static bool core_esil_run_pin(RCore *core, ut64 pc, const char *pc_name, int size) {
	const char *pin = r_anal_pin_at (core->anal, pc);
	if (R_STR_ISEMPTY (pin) || r_str_startswith (pin, "soft.")) {
		return false;
	}
	const char *cmd = r_anal_pin_get (core->anal, pin);
	if (R_STR_ISNOTEMPTY (cmd)) {
		r_core_cmd0 (core, cmd);
	} else if (R_STR_ISNOTEMPTY (core->anal->pincmd)) {
		r_core_cmdf (core, "%s %s", core->anal->pincmd, pin);
		r_core_cmd0 (core, pin);
	} else {
		r_core_cmd0 (core, pin);
	}
	ut64 pin_pc = 0;
	if (!r_esil_reg_read_silent (&core->esil.esil, pc_name, &pin_pc, NULL)) {
		return true;
	}
	if (pin_pc == pc) {
		r_esil_reg_write_silent (&core->esil.esil, pc_name, pc + size);
	}
	return true;
}

R_API bool r_core_esil_init(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->io, false);
	core->esil = (const RCoreEsil){ 0 };
	core->esil.reg = r_reg_new ();
	if (!core->esil.reg) {
		return false;
	}
	REsilRegInterface reg_if = {
		.reg = core,
		.is_reg = core_esil_is_reg,
		.reg_read = core_esil_reg_read,
		.reg_write = core_esil_reg_write,
		.reg_size = core_esil_reg_size,
		.reg_packed_size = core_esil_reg_packed_size,
		.reg_alias = core_esil_reg_alias,
	};
	REsilMemInterface mem_if = {
		.mem = core,
		.mem_switch = core_esil_mem_switch,
		.mem_read = core_esil_mem_read,
		.mem_write = core_esil_mem_write,
	};
	REsilUtilInterface util_if = {
		.user = core,
		.set_bits = core_esil_set_bits,
	};
	if (!r_esil_init (&core->esil.esil, 4096, true, 64, &reg_if, &mem_if, &util_if)) {
		goto init_fail;
	}
	core->esil.esil.anal = core->anal;
	if (!r_esil_set_op (&core->esil.esil, "TODO", core_esil_op_todo, 0, 0, R_ESIL_OP_TYPE_UNKNOWN, NULL) || !r_esil_set_op (&core->esil.esil, "$", core_esil_op_interrupt, 0, 1, R_ESIL_OP_TYPE_UNKNOWN, NULL)) {
		goto op_fail;
	}
	r_strbuf_init (&core->esil.sb.revert);
	core->esil.esil.user = core;
	core->esil.sb.v_reg = r_esil_add_voyeur (&core->esil.esil, &core->esil, core_esil_voyeur_trap_revert_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	core->esil.sb.v_mem = r_esil_add_voyeur (&core->esil.esil, &core->esil, core_esil_voyeur_trap_revert_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	core->esil.sb.v_bits = r_esil_add_voyeur (&core->esil.esil, core, core_esil_voyeur_trap_revert_set_bits, R_ESIL_VOYEUR_SET_BITS);
	core->esil.sb.v_alias = r_esil_add_voyeur (&core->esil.esil, core, core_esil_voyeur_trap_revert_reg_alias, R_ESIL_VOYEUR_REG_ALIAS);
	core->esil.sb.list.free = core_esil_stepback_free;
	return true;
op_fail:
	r_esil_fini (&core->esil.esil);
init_fail:
	r_reg_free (core->esil.reg);
	return false;
}

R_API void r_core_esil_load_arch(RCore *core) {
	R_RETURN_IF_FAIL (core && core->anal && core->anal->arch);
	core->esil.esil.anal = core->anal;
	RArch *arch = core->anal->arch;
	RArchSession *session = arch->session;
	RArchPlugin *plugin = R_UNWRAP2 (session, plugin);
	if (!plugin || !plugin->esilcb || !plugin->regs) {
		// This doesn't count as fail
		return;
	}
	r_arch_esilcb (arch, &core->esil.esil, R_ARCH_ESIL_ACTION_INIT);
	char *rp = plugin->regs (session);
	if (!rp) {
		R_LOG_WARN ("Couldn't set reg profile");
		return;
	}
	r_reg_set_profile_string (core->esil.reg, rp);
	free (rp);
}

R_API void r_core_esil_unload_arch(RCore *core) {
	R_RETURN_IF_FAIL (core && core->anal && core->anal->arch);
	RArch *arch = core->anal->arch;
	RArchSession *session = arch->session;
	RArchPlugin *plugin = R_UNWRAP2 (session, plugin);
	if (!plugin || !plugin->esilcb) {
		return;
	}
	r_arch_esilcb (arch, &core->esil.esil, R_ARCH_ESIL_ACTION_FINI);
}

R_API bool r_core_esil_run_expr_at(RCore *core, const char *expr, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (expr && core && core->anal && core->anal->arch && core->io && core->esil.reg, false);
	core->esil.esil.anal = core->anal;
	const char *pc_name = r_reg_alias_getname (core_esil_reg (core), R_REG_ALIAS_PC);
	if (!pc_name) {
		R_LOG_ERROR ("CoreEsil reg profile has no pc register");
		return false;
	}
	ut64 pc;
	if (!r_esil_reg_read_silent (&core->esil.esil, pc_name, &pc, NULL)) {
		R_LOG_ERROR ("Couldn't read from PC register");
		return false;
	}
	const bool trap_revert = core_esil_trap_revert_start (core, pc_name, pc);
	r_esil_reg_write_silent (&core->esil.esil, pc_name, addr);
	if (r_esil_parse (&core->esil.esil, expr) || !core->esil.esil.trap) {
		if (trap_revert) {
			core_esil_record_stepback (core);
			core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		}
		return true;
	}
	if (trap_revert) {
		// disable trap_revert voyeurs
		core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		char *expr = r_strbuf_drain_nofree (&core->esil.sb.revert);
		// revert all changes
		r_esil_parse (&core->esil.esil, expr);
		free (expr);
	} else {
		r_esil_reg_write_silent (&core->esil.esil, pc_name, pc);
	}
	if (R_STR_ISNOTEMPTY (core->esil.cmds.trap)) {
		core_esil_cmd (core, core->esil.cmds.trap, pc, core->esil.esil.trap_code);
	}
	return false;
}

R_API bool r_core_esil_single_step(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->anal && core->anal->arch && core->io && core->esil.reg, false);
	core->esil.esil.anal = core->anal;
	const char *pc_name = r_reg_alias_getname (core_esil_reg (core), R_REG_ALIAS_PC);
	if (!pc_name) {
		R_LOG_ERROR ("CoreEsil reg profile has no pc register");
		return false;
	}
	ut64 pc;
	if (!r_esil_reg_read_silent (&core->esil.esil, pc_name, &pc, NULL)) {
		R_LOG_ERROR ("Couldn't read from PC register");
		return false;
	}
	const ut64 old_pc = pc;
	bool trap_revert = false;
	core->esil.esil.trap = R_ANAL_TRAP_NONE;
	core->esil.esil.trap_code = 0;
	ut32 trap_code = R_ANAL_TRAP_UNALIGNED;
	const int align = R_MAX (1, r_arch_info (core->anal->arch, R_ARCH_INFO_CODE_ALIGN));
	if (pc % align) {
		goto trap;
	}
	trap_code = R_ANAL_TRAP_INVALID;
	const int eperm = core->esil.esil.exectrap? R_PERM_X: 0;
	RIORegion region;
	const bool has_region = r_io_get_region_at (core->io, &region, pc);
	if (has_region) {
		if (eperm && ! (region.perm & eperm)) {
			trap_code = R_ANAL_TRAP_EXEC_ERR;
			goto trap;
		}
	} else if (!r_io_is_valid_offset (core->io, pc, eperm)) {
		// unmapped offsets can still hold code when io.cache is enabled
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
		R_LOG_ERROR ("Couldn't read data to decode from 0x%" PFMT64x, pc);
		return false;
	}
	// intentionally not using r_anal_op here, because this function is a fucking fever dream
	RArchSession *as = r_ref (core->anal->arch->session);
	if (!as) {
		return false;
	}
	RAnalOp op;
	r_anal_op_init (&op);
	r_anal_op_set_bytes (&op, pc, buf, max_opsize);
	if (!r_arch_session_decode (as, &op, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL)) {
		R_LOG_ERROR ("COuldn't decode instruction at 0x%" PFMT64x, pc);
		r_anal_op_fini (&op);
		r_unref (as);
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
		// maybe do something about arch, bits and endian shit here
		// difficult, because that could mean a different reg profile,
		// which would invalidate some previous steps
		r_anal_hint_free (hint);
	}
	const bool has_esil = R_STR_ISNOTEMPTY (R_STRBUF_SAFEGET (&op.esil));
	const bool invalid_op = !has_esil && (op.type == R_ANAL_OP_TYPE_ILL || op.type == R_ANAL_OP_TYPE_TRAP || op.type == R_ANAL_OP_TYPE_UNK);
	if (invalid_op) {
		trap_code = R_ANAL_TRAP_INVALID;
		goto op_trap;
	}
	if (op.size < 1) {
		trap_code = R_ANAL_TRAP_INVALID;
		goto op_trap;
	}
	if (has_region && !r_itv_contain (region.itv, pc + op.size - 1)) {
		trap_code = R_ANAL_TRAP_INVALID;
		goto op_trap;
	}
	trap_revert = core_esil_trap_revert_start (core, pc_name, old_pc);
	pc += op.size;
	const ut64 ds_addr = pc;
	const bool has_delay = op.delay > 0;
	if (core_esil_run_pin (core, old_pc, pc_name, op.size)) {
		r_anal_op_fini (&op);
		goto skip;
	}
	REsil *trace_esil = R_UNWRAP4 (core, dbg, anal, esil);
	if (trace_esil && trace_esil->trace) {
		r_esil_trace_op (trace_esil, &op);
	}
	char *expr = r_strbuf_drain_nofree (&op.esil);
	r_esil_reg_write_silent (&core->esil.esil, pc_name, pc);
	r_anal_op_fini (&op);
	if (R_STR_ISNOTEMPTY (core->esil.cmds.step)) {
		if (core_esil_cmd (core, core->esil.cmds.step, old_pc, 0)) {
			free (expr);
			// cmd_step ran instead of the ESIL expression; its side effects
			// can't be reverted by a PC-only stepback, so don't record one
			if (trap_revert) {
				r_strbuf_fini (&core->esil.sb.revert);
				core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
			}
			goto skip;
		}
	}
	const bool suc = r_esil_parse (&core->esil.esil, expr) || !core->esil.esil.trap;
	free (expr);
	if (suc) {
		if (has_delay && core->esil.esil.delay &&
			!core_esil_step_delay_slot (core, as, pc_name, ds_addr, max_opsize)) {
			trap_code = R_ANAL_TRAP_INVALID;
			r_unref (as);
			goto trap;
		}
		core_esil_align_pc (core, pc_name);
skip:
		if (trap_revert) {
			core_esil_record_stepback (core);
			core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		}
		r_unref (as);
		if (R_STR_ISNOTEMPTY (core->esil.cmds.step_out)) {
			core_esil_cmd (core, core->esil.cmds.step_out, old_pc, 0);
		}
		return true;
	}
	const int trap_type = core->esil.esil.trap? core->esil.esil.trap: R_ANAL_TRAP_INVALID;
	trap_code = core->esil.esil.trap_code;
	if (!trap_code) {
		trap_code = trap_type;
	}
	if (trap_revert) {
		const bool trap_revert_config = core->esil.cfg & R_CORE_ESIL_TRAP_REVERT_CONFIG;
		// disable trap_revert voyeurs
		core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
		char *expr = r_strbuf_drain_nofree (&core->esil.sb.revert);
		// revert all changes
		r_esil_parse (&core->esil.esil, expr);
		free (expr);
		if (!trap_revert_config) {
			r_esil_reg_write_silent (&core->esil.esil, pc_name, pc);
		}
		core->esil.esil.trap = trap_type;
		core->esil.esil.trap_code = trap_code;
		r_unref (as);
		goto trap;
	}
	r_unref (as);
	goto trap;
op_trap:
	r_unref (as);
	r_anal_op_fini (&op);
trap:
	if (!core->esil.esil.trap) {
		core->esil.esil.trap = trap_code;
	}
	if (!core->esil.esil.trap_code) {
		core->esil.esil.trap_code = trap_code;
	}
	if (R_STR_ISNOTEMPTY (core->esil.cmds.trap)) {
		core_esil_cmd (core, core->esil.cmds.trap, old_pc, trap_code);
	}
	return false;
}

R_API void r_core_esil_stepback(RCore *core) {
	R_RETURN_IF_FAIL (core && core->io && core->anal && core->esil.reg);
	if (!r_list_length (&core->esil.sb.list)) {
		// not an error
		return;
	}
	RCoreEsilStepBack *cesb = r_list_pop (&core->esil.sb.list);
	core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT;
	r_esil_parse (&core->esil.esil, cesb->expr);
	core_esil_stepback_free (cesb);
}

R_API void r_core_esil_set_max_stepback(RCore *core, ut32 max_stepback) {
	R_RETURN_IF_FAIL (core && core->esil.sb.list.free);
	core->esil.sb.max = max_stepback;
	while (r_list_length (&core->esil.sb.list) > max_stepback) {
		core_esil_stepback_free (r_list_pop_head (&core->esil.sb.list));
	}
}

R_API void r_core_esil_fini(RCoreEsil *cesil) {
	R_RETURN_IF_FAIL (cesil);
	core_esil_stepback_fini (&cesil->esil, &cesil->sb);
	r_esil_fini (&cesil->esil);
	if (cesil->reg) {
		r_reg_free (cesil->reg);
		cesil->reg = NULL;
	}
	core_esil_cmds_fini (&cesil->cmds);
	cesil->esil = (const REsil){ 0 };
}
