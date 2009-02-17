/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_var.h"
#include "r_cons.h"

struct r_var_t *r_var_new()
{
	struct r_var_t *var = MALLOC_STRUCT(struct r_var_t);
	r_var_init(var);
	return var;
}

void r_var_free(struct r_var_t *var)
{
	free(var);
}

int r_var_init(struct r_var_t *var)
{
	INIT_LIST_HEAD(&(var->vartypes));
	INIT_LIST_HEAD(&(var->vars));

	r_var_type_add(var, "char", 1, "b");
	r_var_type_add(var, "byte", 1, "b");
	r_var_type_add(var, "int", 4, "d");
	r_var_type_add(var, "int32", 4, "d");
	r_var_type_add(var, "dword", 4, "x");
	r_var_type_add(var, "float", 4, "f");
	r_var_anal_reset(var);

	return R_TRUE;
}

/* data.c */

int r_var_type_add(struct r_var_t *var, const char *typename, int size, const char *fmt)
{
	struct r_var_type_t *d = (struct r_var_type_t *)
		malloc(sizeof(struct r_var_type_t));
	strncpy(d->name, typename, sizeof(d->name));
	strncpy(d->fmt, fmt, sizeof(d->fmt));
	d->size = size;
	list_add(&(d->list), &var->vartypes);
	
	return R_TRUE;
}

int r_var_type_del(struct r_var_t *var, const char *typename)
{
	struct list_head *pos;

	if (*typename==' ') typename = typename+1;

	list_for_each(pos, &var->vartypes) {
		struct r_var_type_t *d = (struct r_var_type_t *)
			list_entry(pos, struct r_var_type_t, list);
		if (!strcmp(typename, d->name)) {
			list_del(&(d->list));
			return 1;
		}
	}
	return 0;
}

int r_var_type_list(struct r_var_t *var)
{
	struct list_head *pos;
	u64 ret = 0;

	list_for_each(pos, &var->vartypes) {
		struct r_var_type_t *d = (struct r_var_type_t *)
			list_entry(pos, struct r_var_type_t, list);
		printf("%s %d %s\n", d->name, d->size, d->fmt);
	}
	return ret;
}

struct r_var_type_t *r_var_type_get(struct r_var_t *var, const char *datatype)
{
	struct list_head *pos;

	list_for_each(pos, &var->vartypes) {
		struct r_var_type_t *d = (struct r_var_type_t *)
			list_entry(pos, struct r_var_type_t, list);
		//eprintf("---(%s)(%s)\n", d->name, datatype);
		if (!strcmp(datatype, d->name))
			return d;
	}
	return NULL;
}

/* vars.c */

int r_var_add(struct r_var_t *v, u64 addr, u64 eaddr, int delta, int type, const char *vartype, const char *name, int arraysize)
{
	struct r_var_item_t *var = MALLOC_STRUCT(struct r_var_item_t);
	/* TODO: check of delta inside funframe */
	if (strchr(name, ' ') || strchr(vartype,' ')) {
		fprintf(stderr, "r_var_add: Invalid name/type\n");
		return 0;
	}
	strncpy(var->name, name, sizeof(var->name));
	strncpy(var->vartype, vartype, sizeof(var->vartype));
	var->delta = delta;
	var->type = type;
	var->addr = addr;
	var->eaddr = eaddr;
	var->arraysize = arraysize;
	INIT_LIST_HEAD(&(var->access));
	list_add(&(var->list), &v->vars);
	return 1;
}

int r_var_add_access(struct r_var_t *var, u64 addr, int delta, int type, int set)
{
	u64 from = 0LL, to = 0LL;
	struct list_head *pos;
	struct r_var_item_t *v;
	int reloop = 0;

	_reloop:
	list_for_each(pos, &var->vars) {
		v = (struct r_var_item_t*)list_entry(pos, struct r_var_item_t, list);
		if (addr >= v->addr) {
			//if (!strcmp(name, v->name)) {
			if (delta == v->delta && type == v->type) {
				struct r_var_access_t *xs = MALLOC_STRUCT(struct r_var_access_t);
				xs->addr = addr;
				xs->set = set;
				/* add var access here */
				list_add(&(xs->list), &(v->access));
				return 1;
			}
		}
	}
	/* automatic init */
	/* detect function in CF list */
	from = to = 0LL;
	// XXX USE RMETA HERE!!
	if ( data_get_fun_for(addr, &from, &to) ) {
		char varname[32];
		if (delta < 0) {
			delta = -delta;
			sprintf(varname, "arg_%d", delta);
		} else sprintf(varname, "var_%d", delta);
		//eprintf("0x%08llx: NEW LOCAL VAR %d\n", from, delta);
		r_var_add(var, from, to, delta, R_VAR_TYPE_LOCAL, "int32", varname, 1);
		if (reloop) {
			#warning THIS IS BUGGY: SHOULD NEVER HAPPEN
			fprintf(stderr, "LOOPING AT 0x%08llx NOT ADDING AN ACCESS\n", addr);
			return 0;
		}
		reloop=1;
		goto _reloop;
		return r_var_add_access(var, addr, delta, type, set);
	} else fprintf(stderr, "Cannot find bounding function at 0x%08llx\n", addr);
	return 0;
}

/* XXX: this is a static method..no need for $self argument */
const char *r_var_type_to_string(int type)
{
	switch(type) {
	case R_VAR_TYPE_GLOBAL: return "global";
	case R_VAR_TYPE_LOCAL:  return "local";
	case R_VAR_TYPE_ARG:    return "arg";
	case R_VAR_TYPE_ARGREG: return "fastarg";
	}
	return "(?)";
}

#if 0
/* This stuff belongs to the plugins realm */
u32 var_dbg_read(int delta)
{
	/* XXX: EBP ONLY FOR X86 */
	u32 ret;
	u64 foo = get_offset("ebp");
	foo-=delta;
	radare_read_at(foo, (u8*)&ret, 4);
	return ret;
}
#endif

int r_var_item_print(struct r_var_t *var, struct r_var_item_t * v)
{
	struct r_var_type_t *t = r_var_type_get(var, v->vartype);
	if (t == NULL) {
		u32 value = 0; //XXX var_dbg_read(v->delta);
		// TODO: use var type to 
		r_cons_printf("%x", value);
	} else {
#if 0
		u8 buf[1024];
		int size = v->arraysize * t->size;
		u64 foo = get_offset("ebp");
		foo -= v->delta;
		//XXX radare_read_at(foo, buf, size);
		//eprintf("PRINT_MEM(%llx,%d,%s)\n", foo, size, t->fmt);
		//XXX print_mem(foo, buf, size, t->fmt, config.endian);
#endif
	}
	return 0;
}

/* CFV */
int r_var_list_show(struct r_var_t *var, u64 addr)
{
	struct list_head *pos;
	struct r_var_item_t *v;

	list_for_each(pos, &var->vars) {
		v = (struct r_var_item_t*)list_entry(pos, struct r_var_item_t, list);
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			//u32 value = var_dbg_read(v->delta);
			if (v->arraysize>1) {
				r_cons_printf("%s %s %s[%d] = ",
					r_var_type_to_string(v->type),
					v->vartype, v->arraysize, v->name);
			} else {
				r_cons_printf("%s %s %s = ",
					r_var_type_to_string(v->type), v->vartype, v->name);
			}
			r_var_item_print(var, v);
			/* TODO: detect pointer to strings and so on */
#if 0
			if (string_flag_offset(buf, value, 0))
				r_cons_printf(" ; points to: %s\n", buf);
			else 
#endif
			r_cons_newline();
		}
	}

	return 0;
}

/* 0,0 to list all */
int r_var_list(struct r_var_t *var, u64 addr, int delta)
{
	struct list_head *pos, *pos2;
	struct r_var_item_t*v;
	struct r_var_access_t *x;

	list_for_each(pos, &var->vars) {
		v = (struct r_var_item_t*)list_entry(pos, struct r_var_item_t, list);
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			printf("0x%08llx - 0x%08llx type=%s type=%s name=%s delta=%d array=%d\n",
				v->addr, v->eaddr, r_var_type_to_string(v->type),
				v->vartype, v->name, v->delta, v->arraysize);
			list_for_each_prev(pos2, &v->access) {
				x = (struct r_var_access_t *)list_entry(pos2, struct r_var_access_t, list);
				printf("  0x%08llx %s\n", x->addr, x->set?"set":"get");
			}
		}
	}

	return 0;
}

/* analize.c */

// XXX move to code.h
void r_var_anal_reset(struct r_var_t *var)
{
	memset(&var->anal, '\0', sizeof(var->anal));
	var->anal_size = 0;
}

int r_var_anal_add(struct r_var_t *var, int type, int delta)
{
	int i, hole = -1;
	for(i=0;i<R_VAR_ANAL_MAX;i++) {
		if (var->anal[i].type == type && var->anal[i].delta == delta) {
			var->anal[i].count++;
			return 0;
		} else
		if (var->anal[i].type==R_VAR_TYPE_NONE && hole==-1) {
			hole = i;
		}
	}
	if (hole==-1) {
		fprintf(stderr, "analyze.c: No space left in var pool\n");
		return -1;
	}
	var->anal[hole].type  = type;
	var->anal[hole].delta = delta;
	return 1;
}

int r_var_anal_get(struct r_var_t *var, int type)
{
	int i, ctr = 0;
	for(i=0;i<R_VAR_ANAL_MAX;i++) {
		if (var->anal[i].type == type)
			ctr++;
	}
	return ctr;
}
