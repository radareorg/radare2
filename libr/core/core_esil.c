/* radare - LGPL - Copyright 2024 - condret */

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
	r_unref (ri);
	return ri->size;
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
	if (!(cesil->cfg & R_CORE_ESIL_REVERT)) {
		return;
	}
	if (R_UNLIKELY (!r_strbuf_length (&cesil->trap_revert))) {
		r_strbuf_setf (&cesil->trap_revert, "0x%"PFMT64x",%s,:=", old, name);
		return;
	}
	r_strbuf_appendf (&cesil->trap_revert, ",0x%"PFMT64x",%s,:=", old, name);
}

static void core_esil_voyeur_trap_revert_mem_write (void *user, ut64 addr,
	const ut8 *old, const ut8 *buf, int len) {
	RCoreEsil *cesil = user;
	if (!(cesil->cfg & R_CORE_ESIL_REVERT)) {
		return;
	}
	int i;
	if (R_UNLIKELY (!r_strbuf_length (&cesil->trap_revert))) {
		r_strbuf_setf (&cesil->trap_revert, "0x%02x,0x%"PFMT64x",=[1]",
			*old, addr);
		i = 1;
	} else {
		i = 0;
	}
	for (;i < len; i++) {
		//TODO: optimize this after breaking
		r_strbuf_appendf (&cesil->trap_revert, ",0x%02x,0x%"PFMT64x",=[1]",
			old[i], addr + i);
	}
}

R_API bool r_core_esil_init(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->io, false);
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
	if (!r_esil_set_op (&core->esil.esil, "TODO", core_esil_op_todo,
		0, 0, R_ESIL_OP_TYPE_UNKNOWN)) {
		goto op_fail;
	}
	r_strbuf_init (&core->esil.trap_revert);
	core->esil.esil.user = core;
	core->esil.tr_reg = r_esil_add_voyeur (&core->esil.esil, &core->esil,
		core_esil_voyeur_trap_revert_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	core->esil.tr_mem = r_esil_add_voyeur (&core->esil.esil, &core->esil,
		core_esil_voyeur_trap_revert_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
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
	cesil->esil = (const REsil){0};
}
