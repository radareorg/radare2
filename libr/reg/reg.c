/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_reg.h>
#include <r_util.h>

/* lifecycle */

static void r_reg_free_internal(struct r_reg_t *reg)
{
}

R_API struct r_reg_t *r_reg_free(struct r_reg_t *reg)
{
	if (reg) {
		// TODO: free more things here
		free(reg);
	}
	return NULL;
}


R_API struct r_reg_t *r_reg_init(struct r_reg_t *reg)
{
	if (reg) {
	}
	return reg;
}

R_API struct r_reg_t *r_reg_new()
{
	struct r_reg_t *r = MALLOC_STRUCT(struct r_reg_t);
	return r_reg_init(r);
}

R_API int r_reg_set_profile_string(struct r_reg_t *reg, const char *profile)
{
	int ret = R_FALSE;
	// ADD PARSING STUFF HERE
	printf("LOADING(%s)\n", profile);
	r_reg_free_internal(reg);
	return ret;
}

R_API int r_reg_set_profile(struct r_reg_t *reg, const char *profile)
{
	int ret = R_FALSE;
	char *str, *file;
	const char *base;
	/* TODO: append .regs extension to filename */
	str = r_file_slurp(profile, NULL);
	if (str == NULL) {
 		// XXX we must define this varname in r_lib.h /compiletime/
		base = r_sys_getenv("LIBR_PLUGINS");
		if (base) {
			file = r_str_concat(strdup(base), profile);
			str = r_file_slurp(profile, NULL);
			free(file);
		}
	}
	if (str)
		ret = r_reg_set_profile_string(reg, str);
	return ret;
}

R_API struct r_reg_item_t *r_reg_get(struct r_reg_t *reg, const char *name)
{
	struct list_head *pos;
	struct r_reg_item_t *r;
	int i;

	for(i=0;i<R_REG_TYPE_LAST;i++) {
		list_for_each(pos, &reg->regset[i].regs) {
			r = list_entry(pos, struct r_reg_item_t, list);
			if (!strcmp(r->name, name))
				return r;
		}
	}
	return NULL;
}

R_API struct list_head *r_reg_get_list(struct r_reg_t *reg, int type)
{
	if (type < 0 || type > R_REG_TYPE_LAST)
		return NULL;
	return &reg->regset[type].regs;
}

/* vala example */
/*
	Debug dbg = new Debug();
	dbg.reg = new Register();

	foreach (unowned var foo in dbg.reg.get_list(Register.Type.GPR)) {
		if (foo.size == 32)
		stdout.printf("Register %s: 0x%08llx\n",
			foo.name, foo.size, dbg.reg.get_value(foo));
	}
*/
