/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_reg.h>
#include <r_util.h>

R_LIB_VERSION (r_reg);

static const char *types[R_REG_TYPE_LAST + 1] = {
	"gpr", "drx", "fpu", "mmx", "xmm", "flg", "seg", NULL
};

// Take the 32bits name of a register, and return the 64 bit name of it.
// If there is no equivalent 64 bit register return NULL.
R_API const char *r_reg_32_to_64(RReg *reg, const char *rreg32) {
	// OMG this is shit...
	int i, j = -1;
	RListIter *iter;
	RRegItem *item;
	for (i = 0; i < R_REG_TYPE_LAST; ++i) {
		r_list_foreach (reg->regset[i].regs, iter, item) {
			if (item->size == 32 && !r_str_casecmp (rreg32, item->name)) {
				j = item->offset;
				break;
			}
		}
	}
	if (j != -1) {
		for (i = 0; i < R_REG_TYPE_LAST; ++i) {
			r_list_foreach (reg->regset[i].regs, iter, item) {
				if (item->offset == j && item->size == 64) {
					return item->name;
				}
			}
		}
	}
	return NULL;
}

// Take the 64 bits name of a register, and return the 32 bit name of it.
// If there is no equivalent 32 bit register return NULL.
R_API const char *r_reg_64_to_32(RReg *reg, const char *rreg64) {
	int i, j = -1;
	RListIter *iter;
	RRegItem *item;
	for (i = 0; i < R_REG_TYPE_LAST; ++i) {
		r_list_foreach (reg->regset[i].regs, iter, item) {
			if (item->size == 64 && !r_str_casecmp (rreg64, item->name)) {
				j = item->offset;
				break;
			}
		}
	}
	if (j != -1) {
		for (i = 0; i < R_REG_TYPE_LAST; ++i) {
			r_list_foreach (reg->regset[i].regs, iter, item) {
				if (item->offset == j && item->size == 32) {
					return item->name;
				}
			}
		}
	}
	return NULL;
}

R_API const char *r_reg_get_type(int idx) {
	return (idx >= 0 && idx < R_REG_TYPE_LAST) ? types[idx] : NULL;
}

R_API int r_reg_type_by_name(const char *str) {
	int i;
	for (i = 0; i < R_REG_TYPE_LAST && types[i]; i++) {
		if (!strcmp (types[i], str)) {
			return i;
		}
	}
	if (!strcmp (str, "all")) {
		return R_REG_TYPE_ALL;
	}
	return -1;
}

R_API void r_reg_item_free(RRegItem *item) {
	free (item->name);
	free (item->flags);
	free (item);
}

R_API int r_reg_get_name_idx(const char *type) {
	if (!type || !*type) {
		return -1;
	}
	switch (*type | (type[1] << 8)) {
	/* flags */
	case 'Z' + ('F' << 8): return R_REG_NAME_ZF;
	case 'S' + ('F' << 8): return R_REG_NAME_SF;
	case 'C' + ('F' << 8): return R_REG_NAME_CF;
	case 'O' + ('F' << 8): return R_REG_NAME_OF;
	/* gpr */
	case 'P' + ('C' << 8): return R_REG_NAME_PC;
	case 'S' + ('R' << 8): return R_REG_NAME_SR;
	case 'L' + ('R' << 8): return R_REG_NAME_LR;
	case 'S' + ('P' << 8): return R_REG_NAME_SP;
	case 'B' + ('P' << 8): return R_REG_NAME_BP;
	case 'S' + ('N' << 8): return R_REG_NAME_SN;
	/* args */
	case 'A' + ('0' << 8): return R_REG_NAME_A0;
	case 'A' + ('1' << 8): return R_REG_NAME_A1;
	case 'A' + ('2' << 8): return R_REG_NAME_A2;
	case 'A' + ('3' << 8): return R_REG_NAME_A3;
	case 'A' + ('4' << 8): return R_REG_NAME_A4;
	case 'A' + ('5' << 8): return R_REG_NAME_A5;
	case 'A' + ('6' << 8): return R_REG_NAME_A6;
	case 'A' + ('7' << 8): return R_REG_NAME_A7;
	case 'A' + ('8' << 8): return R_REG_NAME_A8;
	case 'A' + ('9' << 8): return R_REG_NAME_A9;
	/* return values */
	case 'R' + ('0' << 8): return R_REG_NAME_R0;
	case 'R' + ('1' << 8): return R_REG_NAME_R1;
	case 'R' + ('2' << 8): return R_REG_NAME_R2;
	case 'R' + ('3' << 8): return R_REG_NAME_R3;
	}
	return -1;
}

R_API int r_reg_set_name(RReg *reg, int role, const char *name) {
	if (role >= 0 && role < R_REG_NAME_LAST) {
		reg->name[role] = r_str_dup (reg->name[role], name);
		return true;
	}
	return false;
}

R_API const char *r_reg_get_name(RReg *reg, int role) {
	if (reg && role >= 0 && role < R_REG_NAME_LAST) {
		return reg->name[role];
	}
	return NULL;
}

static const char *roles[R_REG_NAME_LAST + 1] = {
	"PC", "SP", "SR", "BP", "LR",
	"A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9",
	"R0", "R1", "R2", "R3",
	"ZF", "SF", "CF", "OF",
	"SN",
	NULL
};

R_API const char *r_reg_get_role(int role) {
	if (role >= 0 && role < R_REG_NAME_LAST) {
		return roles[role];
	}
	return NULL;
}

R_API void r_reg_free_internal(RReg *reg, bool init) {
	ut32 i;

	R_FREE (reg->reg_profile_str);
	R_FREE (reg->reg_profile_cmt);

	for (i = 0; i < R_REG_NAME_LAST; i++) {
		if (reg->name[i]) {
			free (reg->name[i]);
			reg->name[i] = NULL;
		}
	}
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		if (init) {
			r_list_free (reg->regset[i].regs);
			reg->regset[i].regs = r_list_newf ((RListFree)r_reg_item_free);
		} else {
			r_list_free (reg->regset[i].regs);
			reg->regset[i].regs = NULL;
			// Ensure arena is freed and its registered in the pool
			if (!r_list_delete_data (reg->regset[i].pool, reg->regset[i].arena)) {
				r_reg_arena_free (reg->regset[i].arena);
			}
			reg->regset[i].arena = NULL;
			r_list_free (reg->regset[i].pool);
			reg->regset[i].pool = NULL;
		}
	}
	if (!init) {
		r_list_free (reg->allregs);
	}
	reg->size = 0;
}

static int regcmp(RRegItem *a, RRegItem *b) {
	int offa = (a->offset * 16) + a->size;
	int offb = (b->offset * 16) + b->size;
	return offa > offb;
}

R_API void r_reg_reindex(RReg *reg) {
	int i, index;
	RListIter *iter;
	RRegItem *r;
	RList *all = r_list_newf (NULL);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_list_foreach (reg->regset[i].regs, iter, r) {
			r_list_append (all, r);
		}
	}
	r_list_sort (all, (RListComparator)regcmp);
	index = 0;
	r_list_foreach (all, iter, r) {
		r->index = index++;
	}
	r_list_free (reg->allregs);
	reg->allregs = all;
}

R_API RRegItem *r_reg_index_get(RReg *reg, int idx) {
	RRegItem *r;
	RListIter *iter;
	if (idx < 0) {
		return NULL;
	}
	if (!reg->allregs) {
		r_reg_reindex (reg);
	}
	r_list_foreach (reg->allregs, iter, r) {
		if (r->index == idx) {
			return r;
		}
	}
	return NULL;
}

R_API void r_reg_free(RReg *reg) {
	if (!reg) {
		return;
	}
	r_reg_free_internal (reg, false);
	free (reg);
}

R_API RReg *r_reg_new() {
	RRegArena *arena;
	RReg *reg = R_NEW0 (RReg);
	int i;
	if (!reg) {
		return NULL;
	}
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		arena = r_reg_arena_new (0);
		if (!arena) {
			free (reg);
			return NULL;
		}
		reg->regset[i].pool = r_list_newf ((RListFree)r_reg_arena_free);
		reg->regset[i].regs = r_list_newf ((RListFree)r_reg_item_free);
		r_list_push (reg->regset[i].pool, arena);
		reg->regset[i].arena = arena;
	}
	r_reg_arena_push (reg);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		reg->regset[i].cur = r_list_tail (reg->regset[i].pool);
	}
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
	if (!reg || !name) {
		return NULL;
	}
	if (type == R_REG_TYPE_FLG) {
		type = R_REG_TYPE_GPR;
	}
	if (type == -1) {
		i = 0;
		e = R_REG_TYPE_LAST;
	} else {
		i = type;
		e = type + 1;
	}
	for (; i < e; i++) {
		r_list_foreach (reg->regset[i].regs, iter, r) {
			if (r->name && !strcmp (r->name, name)) {
				return r;
			}
		}
	}
	return NULL;
}

R_API RList *r_reg_get_list(RReg *reg, int type) {
	if (type < 0 || type > (R_REG_TYPE_LAST - 1)) {
		return NULL;
	}
	return reg->regset[type].regs;
}

// TODO regsize is in bits, delta in bytes, maybe we should standarize this..
R_API RRegItem *r_reg_get_at(RReg *reg, int type, int regsize, int delta) {
	RList *list = r_reg_get_list (reg, type);
	RRegItem *ri;
	RListIter *iter;
	r_list_foreach (list, iter, ri) {
		if (ri->size == regsize) {
			if (BITS2BYTES (ri->offset) == delta) {
				return ri;
			}
		}
	}
	return NULL;
}

/* return the next register in the current regset that differs from */
R_API RRegItem *r_reg_next_diff(RReg *reg, int type, const ut8 *buf, int buflen, RRegItem *prev_ri, int regsize) {
	int delta, bregsize = BITS2BYTES (regsize);
	RRegArena *arena;
	if (type < 0 || type > (R_REG_TYPE_LAST - 1)) {
		return NULL;
	}
	arena = reg->regset[type].arena;
	delta = prev_ri ? prev_ri->offset + prev_ri->size : 0;
	for (;;) {
		if (delta + bregsize >= arena->size || delta + bregsize >= buflen) {
			break;
		}
		if (memcmp (arena->bytes + delta, buf + delta, bregsize)) {
			RRegItem *ri = r_reg_get_at (reg, type, regsize, delta);
			if (ri) {
				return ri;
			}
		}
		delta += bregsize;
	}
	return NULL;
}

R_API RRegSet *r_reg_regset_get(RReg *r, int type) {
	RRegSet *rs;
	if (type < 0 || type >= R_REG_TYPE_LAST) {
		return NULL;
	}
	rs = &r->regset[type];
	return rs->arena ? rs : NULL;
}
