/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_reg.h>
#include <r_util.h>
#include <list.h>

R_LIB_VERSION (r_reg);

static const char *types[R_REG_TYPE_LAST+1] = {
	"gpr", "drx", "fpu", "mmx", "xmm", "flg", "seg", NULL
};

R_API const char *r_reg_get_type(int idx) {
	if (idx>=0 && idx<R_REG_TYPE_LAST)
		return types[idx];
	return NULL;
}

R_API int r_reg_type_by_name(const char *str) {
	int i;
	for (i=0; i<R_REG_TYPE_LAST && types[i]; i++)
		if (!strcmp (types[i], str))
			return i;
	if (!strcmp (str, "all"))
		return R_REG_TYPE_ALL;
	eprintf ("Unknown register type: '%s'\n", str);
	return -1;
}

R_API void r_reg_item_free(RRegItem *item) {
	free (item->name);
	free (item->flags);
	free (item);
}

R_API int r_reg_get_name_idx(const char *type) {
	if (type && *type != '\0')
		switch (*type | (type[1]<<8)) {
		/* flags */
		case 'z'+('f'<<8): return R_REG_NAME_ZF;
		case 's'+('f'<<8): return R_REG_NAME_SF;
		case 'c'+('f'<<8): return R_REG_NAME_CF;
		case 'o'+('f'<<8): return R_REG_NAME_OF;
		/* gpr */
		case 'p'+('c'<<8): return R_REG_NAME_PC;
		case 's'+('r'<<8): return R_REG_NAME_SR;
		case 's'+('p'<<8): return R_REG_NAME_SP;
		case 'b'+('p'<<8): return R_REG_NAME_BP;
		case 's'+('n'<<8): return R_REG_NAME_SN;
		/* args */
		case 'a'+('0'<<8): return R_REG_NAME_A0;
		case 'a'+('1'<<8): return R_REG_NAME_A1;
		case 'a'+('2'<<8): return R_REG_NAME_A2;
		case 'a'+('3'<<8): return R_REG_NAME_A3;
		case 'a'+('4'<<8): return R_REG_NAME_A4;
		case 'a'+('5'<<8): return R_REG_NAME_A5;
		case 'a'+('6'<<8): return R_REG_NAME_A6;
		/* return values */
		case 'r'+('0'<<8): return R_REG_NAME_R0;
		case 'r'+('1'<<8): return R_REG_NAME_R1;
		case 'r'+('2'<<8): return R_REG_NAME_R2;
		case 'r'+('3'<<8): return R_REG_NAME_R3;
	}
	return -1;
}

R_API int r_reg_set_name(RReg *reg, int role, const char *name) {
	if (role>=0 && role<R_REG_NAME_LAST) {
		reg->name[role] = r_str_dup (reg->name[role], name);
		return true;
	}
	return false;
}

R_API const char *r_reg_get_name(RReg *reg, int role) {
	if (reg && role>=0 && role<R_REG_NAME_LAST)
		return reg->name[role];
	return NULL;
}

R_API void r_reg_free_internal(RReg *reg) {
	int i;

	free (reg->reg_profile_str);
	reg->reg_profile_str = NULL;

	for (i = 0; i < R_REG_NAME_LAST; i++) {
		if (reg->name[i]) {
			free (reg->name[i]);
			reg->name[i] = NULL;
		}
	}
	for (i = 0; i<R_REG_TYPE_LAST; i++) {
		r_list_purge (reg->regset[i].regs);
		reg->regset[i].regs = r_list_newf ((RListFree)r_reg_item_free);
	}
	reg->size = 0;
}

R_API void r_reg_free(RReg *reg) {
	int i;

	if (!reg) 
		return;

	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_list_purge (reg->regset[i].pool);
		reg->regset[i].pool = NULL;
	}
	r_reg_free_internal (reg);
	free (reg);
}

R_API RReg *r_reg_new() {
	RRegArena *arena;
	RReg *reg = R_NEW0 (RReg);
	int i;

	for (i=0; i<R_REG_TYPE_LAST; i++) {
		arena = r_reg_arena_new (0);
		if (!arena) {
			free (reg);
			return NULL;
		}
		reg->regset[i].pool = r_list_newf ((RListFree)r_reg_arena_free);
		reg->regset[i].regs = r_list_newf ((RListFree)r_reg_item_free);
		reg->regset[i].arena = arena;
		//r_list_append (reg->regset[i].pool, arena);
	}
	/* swap arena back and forth to avoid lost reg sets */
	r_reg_arena_swap (reg, false);
	r_reg_arena_swap (reg, false);
	return reg;
}

R_API ut64 r_reg_setv(RReg *reg, const char *name, ut64 val) {
	return r_reg_set_value (reg, r_reg_get (reg, name, -1), val);
}

R_API ut64 r_reg_getv(RReg *reg, const char *name) {
	return r_reg_get_value (reg, r_reg_get (reg, name, -1));
}

R_API RRegItem *r_reg_get(RReg *reg, const char *name, int type) {
	RListIter *iter;
	RRegItem *r;
	int i, e;
	if (!reg || !name)
		return NULL;
	if (type == -1) {
		i = 0;
		e = R_REG_TYPE_LAST;
	} else {
		i = type;
		e = type+1;
	}

	for (; i<e; i++) {
		r_list_foreach (reg->regset[i].regs, iter, r) {
			if (r->name && !strcmp (r->name, name)) {
				return r;
			}
		}
	}
	return NULL;
}

R_API RList *r_reg_get_list(RReg *reg, int type) {
	if (type < 0 || type > (R_REG_TYPE_LAST-1))
		return NULL;
	return reg->regset[type].regs;
}

R_API ut64 r_reg_cmp(RReg *reg, RRegItem *item) {
	ut64 ret, ret2;
	RListIter *it;
	int ptr = !(reg->iters%2);
	int len = (item->size/8); // TODO: must use r_mem_bitcmp or so.. flags not correctly checked
	int off = BITS2BYTES (item->offset);
	RRegArena *dst, *src;
	it = r_list_head (reg->regset[item->type].pool);
	if (!it || !it->n)
		return UT64_MAX;
	src = r_list_head (reg->regset[item->type].pool)->data;
	dst = it->n->data;
	if (off+len>src->size) len = src->size-off;
	if (off+len>dst->size) len = dst->size-off;
	if (len>1 && memcmp (dst->bytes+off, src->bytes+off, len)) {
		r_reg_arena_set (reg, ptr, 0);
		ret = r_reg_get_value (reg, item);
		r_reg_arena_set (reg, !ptr, 0);
		ret2 = r_reg_get_value (reg, item);
		return ret-ret2;
	}
	return 0LL;
}

// TODO regsize is in bits, delta in bytes, maybe we should standarize this..
R_API RRegItem *r_reg_get_at (RReg *reg, int type, int regsize, int delta) {
	RList *list = r_reg_get_list (reg, type);
	RRegItem *ri;
	RListIter *iter;
	r_list_foreach (list, iter, ri) {
		if (ri->size == regsize) {
			if (BITS2BYTES(ri->offset) == delta)
				return ri;
		}
	}
	return NULL;
}

/* return the next register in the current regset that differs from */
R_API RRegItem *r_reg_next_diff(RReg *reg, int type, const ut8* buf, int buflen, RRegItem *prev_ri, int regsize) {
	int bregsize = BITS2BYTES (regsize);
	RRegArena *arena;
	int delta;
	if (type < 0 || type > (R_REG_TYPE_LAST-1))
		return NULL;
	arena = reg->regset[type].arena;
	delta = prev_ri? prev_ri->offset+prev_ri->size: 0;
	for (;;) {
		if (delta+bregsize>=arena->size || delta+bregsize >= buflen)
			break;
		if (memcmp (arena->bytes+delta, buf+delta, bregsize)) {
			RRegItem *ri = r_reg_get_at (reg, type, regsize, delta);
			if (ri) return ri;
		}
		delta += bregsize;
	}
	return NULL;
}

R_API RRegSet *r_reg_regset_get(RReg *r, int type) {
	RRegSet *rs;
	if (type<0 || type>=R_REG_TYPE_LAST)
		return NULL;
	rs = &r->regset[type];
	if (rs->arena)
		return rs;
	return NULL;
}
