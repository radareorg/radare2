/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_debug.h>

/* registers */

R_API int r_debug_reg_sync(struct r_debug_t *dbg, int write)
{
	if (write) {
		dbg->h->reg_write(dbg->pid, dbg->regs);
	} else {
		/* read registers from debugger backend to dbg->regs */
		if (dbg->h && dbg->h->reg_read) {
			free(dbg->oregs);
			dbg->oregs = dbg->regs;
			dbg->h->reg_read(dbg->regs);
		}
	}
}

R_API struct r_debug_regset_t *r_debug_reg_diff(struct r_debug_t *dbg)
{
	return r_debug_regset_diff(dbg->oregs, dbg->regs);
}

R_API u64 r_debug_reg_get(struct r_debug_t *dbg, const char *name)
{
	int i;
	if (dbg->newstate) {
		r_debug_reg_sync(dbg, 0);
		dbg->newstate = 0;
	}
	if (dbg->regs)
	for(i=0; i<dbg->regs->nregs; i++) {
		if (!strcmp(name, dbg->regs->regs[i].name))
			return &dbg->regs->regs[i].value;
	}
	return R_TRUE;
}

R_API int r_debug_reg_set(struct r_debug_t *dbg, const char *name, u64 value)
{
	int i;
	struct r_debug_regset_t *rs = dbg->regs;
	if (rs)
	for(i=0; i<rs->nregs; i++) {
		if (!strcmp(name, rs->regs[i].name))
			return r_debug_regset_set(dbg->regs, i, name, value);
	}
	return R_FALSE;
}

R_API int r_debug_reg_list(struct r_debug_t *dbg, struct r_debug_regset_t *rs)
{
	int i =0;
	if (rs == NULL)
		rs = dbg->regs;
	if (rs)
	for(i=0;i<rs->nregs;i++) {
		struct r_debug_reg_t *r = &rs->regs[i];
		printf("%d %s 0x%08llx\n", i, r->name, r->value);
		/* TODO: add floating point support here */
	}
	return R_TRUE;
}
