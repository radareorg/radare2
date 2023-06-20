/* radare2 - LGPL - Copyright 2023 - condret */

#include <r_esil.h>
#include <r_util.h>

R_API REsilHooks *r_esil_hooks_new(void) {
	REsilHooks *hooks = R_NEW0 (REsilHooks);
	r_return_val_if_fail (hooks, NULL);
	hooks->mem_read_observers = r_id_storage_new (0, UT32_MAX - 1);
	hooks->mem_write_observers = r_id_storage_new (0, UT32_MAX - 1);
	hooks->reg_read_observers = r_id_storage_new (0, UT32_MAX - 1);
	hooks->reg_write_observers = r_id_storage_new (0, UT32_MAX - 1);
	if (!(hooks->mem_read_observers && hooks->mem_write_observers &&
		hooks->reg_read_observers && hooks->reg_write_observers)) {
		r_id_storage_free (hooks->mem_read_observers);
		r_id_storage_free (hooks->mem_write_observers);
		r_id_storage_free (hooks->reg_read_observers);
		r_id_storage_free (hooks->reg_write_observers);
		free (hooks);
		return NULL;
	}
	return hooks;
}

static bool free_hook_cb(void *user, void *data, ut32 id) {
	free (data);
	return true;
}

R_API void r_esil_hooks_free(REsilHooks *hooks) {
	if (hooks) {
		r_id_storage_foreach (hooks->mem_read_observers, free_hook_cb, NULL);
		r_id_storage_foreach (hooks->mem_write_observers, free_hook_cb, NULL);
		r_id_storage_foreach (hooks->reg_read_observers, free_hook_cb, NULL);
		r_id_storage_foreach (hooks->reg_write_observers, free_hook_cb, NULL);
	}
	free (hooks);
}

R_API bool r_esil_set_mem_read_imp(REsil *esil, REsilImpHookMemReadCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_read_implementation) {
		esil->hooks->mem_read_implementation = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->mem_read_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->imr = imp;
	return true;
}

R_API void r_esil_del_mem_read_imp(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_read_implementation);
}

R_API bool r_esil_set_mem_write_imp(REsil *esil, REsilImpHookMemWriteCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_write_implementation) {
		esil->hooks->mem_write_implementation = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->mem_write_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->imw = imp;
	return true;
}

R_API void r_esil_del_mem_write_imp(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_write_implementation);
}

R_API bool r_esil_set_reg_read_imp(REsil *esil, REsilImpHookRegReadCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_read_implementation) {
		esil->hooks->reg_read_implementation = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->reg_read_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->irr = imp;
	return true;
}

R_API void r_esil_del_reg_read_imp(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_read_implementation);
}

R_API bool r_esil_set_reg_write_imp(REsil *esil, REsilImpHookRegWriteCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_write_implementation) {
		esil->hooks->reg_write_implementation = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->reg_write_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->irw = imp;
	return true;
}

R_API void r_esil_del_reg_write_imp(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_write_implementation);
}

R_API bool r_esil_set_mem_read_mod(REsil *esil, REsilModHookMemReadCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_read_modifier) {
		esil->hooks->mem_read_modifier = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->mem_read_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mmr = mod;
	return true;
}

R_API void r_esil_del_mem_read_mod(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_read_modifier);
}

R_API bool r_esil_set_mem_write_mod(REsil *esil, REsilModHookMemWriteCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_write_modifier) {
		esil->hooks->mem_write_modifier = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->mem_write_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mmw = mod;
	return true;
}

R_API void r_esil_del_mem_write_mod(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_write_modifier);
}

R_API bool r_esil_set_reg_read_mod(REsil *esil, REsilModHookRegReadCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_read_modifier) {
		esil->hooks->reg_read_modifier = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->reg_read_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mrr = mod;
	return true;
}

R_API void r_esil_del_reg_read_mod(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_read_modifier);
}

R_API bool r_esil_set_reg_write_mod(REsil *esil, REsilModHookRegWriteCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_write_modifier) {
		esil->hooks->reg_write_modifier = R_NEW (REsilHook);
	}
	REsilHook *hook = esil->hooks->reg_write_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mrw = mod;
	return true;
}

R_API void r_esil_del_reg_write_mod(REsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_write_modifier);
}

static ut32 add_hook_to_idstorage(RIDStorage *st, void *fcn, void *user) {
	r_return_val_if_fail (st && fcn, UT32_MAX);
	REsilHook *hook = R_NEW (REsilHook);
	r_return_val_if_fail (hook, UT32_MAX);
	hook->fcn = fcn;
	hook->user = user;
	ut32 ret;
	if (!r_id_storage_add (st, hook, &ret)) {
		free (hook);
		return UT32_MAX;
	}
	return ret;
}

R_API ut32 r_esil_add_mem_read_obs(REsil *esil, REsilObsHookMemReadCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->mem_read_observers, obs, user);
}

R_API ut32 r_esil_add_mem_write_obs(REsil *esil, REsilObsHookMemWriteCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->mem_write_observers, obs, user);
}

R_API ut32 r_esil_add_reg_read_obs(REsil *esil, REsilObsHookRegReadCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->reg_read_observers, obs, user);
}

R_API ut32 r_esil_add_reg_write_obs(REsil *esil, REsilObsHookRegWriteCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->mem_read_observers, obs, user);
}

R_API void r_esil_del_mem_read_obs(REsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->mem_read_observers, id));
}

R_API void r_esil_del_mem_write_obs(REsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->mem_write_observers, id));
}

R_API void r_esil_del_reg_read_obs(REsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->reg_read_observers, id));
}

R_API void r_esil_del_reg_write_obs(REsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->mem_write_observers, id));
}

R_API bool r_esil_mem_read_at1(REsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks &&
		esil->hooks->mem_read_implementation, false);
	return esil->hooks->mem_read_implementation->imr (
		esil->hooks->mem_read_implementation->user, addr, buf, len);
}

typedef struct foreach_mem_user_t {
	ut64 addr;
	int len;
	ut8 *buf;
	ut8 *dup;
} MemUser;

static bool mem_read_obsv_wrap(void *user, void *data, ut32 id) {
	MemUser *mu = (MemUser *)user;
	REsilHook *hook = (REsilHook *)data;
	memcpy (mu->dup, mu->buf, mu->len);	//this assures the observer cannot modify the buffer
	hook->omr (hook->user, mu->addr, mu->dup, mu->len);
	return true;
}

R_API bool r_esil_mem_read_at2(REsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks, false);
	if (esil->hooks->mem_read_modifier) {
		if (!esil->hooks->mem_read_modifier->mmr (
			esil->hooks->mem_read_modifier->user, esil,
			addr, buf, len)) {
			return true;
		}
	}
	if (r_esil_mem_read_at1 (esil, addr, buf, len)) {
		MemUser mu = { addr, len, buf, R_NEWS (ut8, len)};
		if (mu.dup) {
			r_id_storage_foreach (esil->hooks->mem_read_observers,
				mem_read_obsv_wrap, &mu);
			free (mu.dup);
		}
		return true;
	}
	return false;
}

R_API bool r_esil_mem_write_at1(REsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks &&
		esil->hooks->mem_write_implementation, false);
	return esil->hooks->mem_write_implementation->imw (
		esil->hooks->mem_write_implementation->user, addr, buf, len);
}

static bool mem_write_obsv_wrap(void *user, void *data, ut32 id) {
	MemUser *mu = (MemUser *)user;
	REsilHook *hook = (REsilHook *)data;
	memcpy (mu->dup, mu->buf, mu->len);
	hook->omw (hook->user, mu->addr, mu->dup, mu->len);
	return true;
}

R_API bool r_esil_mem_write_at2(REsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks, false);
	if (esil->hooks->mem_write_modifier) {
		if (!esil->hooks->mem_write_modifier->mmw (
			esil->hooks->mem_write_implementation->user,
			esil, addr, buf, len)) {
			return true;
		}
	}
	MemUser mu = { addr, len, buf, R_NEWS (ut8, len)};
	if (mu.dup) {
		r_id_storage_foreach (esil->hooks->mem_write_observers,
			mem_write_obsv_wrap, &mu);
		free (mu.dup);
	}
	return r_esil_mem_write_at1 (esil, addr, buf, len);
}

R_API bool r_esil_reg_read1(REsil *esil, const char *regname, ut64 *val, ut32 *size) {
	r_return_val_if_fail (val && regname && esil && esil->hooks &&
		esil->hooks->reg_read_implementation, false);
	return esil->hooks->reg_read_implementation->irr (
		esil->hooks->reg_read_implementation->user, regname, val, size);
}

typedef struct reg_user_t {
	const char *regname;
	const ut64 val;
} RegUser;

static bool reg_read_obsv_wrap(void *user, void *data, ut32 id) {
	RegUser *ru = (RegUser *)user;
	REsilHook *hook = (REsilHook *)data;
	hook->orr (hook->user, ru->regname);
	return true;
}

R_API bool r_esil_reg_read2(REsil *esil, const char *regname, ut64 *val, ut32 *size) {
	r_return_val_if_fail (val && regname && esil && esil->hooks, 0LL);
	if (esil->hooks->reg_read_modifier) {
		if (!esil->hooks->reg_read_modifier->mrr (
			esil->hooks->reg_read_modifier->user, esil, regname, val, size)) {
			return true;
		}
	}
	RegUser ru = {regname, 0ULL};
	r_id_storage_foreach (esil->hooks->reg_read_observers, reg_read_obsv_wrap, &ru);
	return r_esil_reg_read1 (esil, regname, val, size);
}

R_API bool r_esil_reg_write1(REsil *esil, const char *regname, ut64 val) {
	r_return_val_if_fail (regname && esil && esil->hooks &&
		esil->hooks->reg_write_implementation, false);
	return esil->hooks->reg_write_implementation->irw (
		esil->hooks->reg_write_implementation->user, regname, val);
}

static bool reg_write_obsv_wrap(void *user, void *data, ut32 id) {
	RegUser *ru = (RegUser *)user;
	REsilHook *hook = (REsilHook *)data;
	hook->orw (hook->user, ru->regname, ru->val);
	return true;
}

R_API bool r_esil_reg_write2(REsil *esil, const char *regname, ut64 val) {
	r_return_val_if_fail (regname && esil && esil->hooks, false);
	if (esil->hooks->reg_write_modifier) {
		if (!esil->hooks->reg_write_modifier->mrw (
			esil->hooks->reg_write_modifier->user, esil, regname, val)) {
			return true;
		}
	}
	RegUser ru = {regname, val};
	r_id_storage_foreach (esil->hooks->reg_write_observers, reg_write_obsv_wrap, &ru);
	return r_esil_reg_write1 (esil, regname, val);
}
