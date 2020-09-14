/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <r_reg.h>
#include <r_util.h>

R_LIB_VERSION (r_reg);

static const char *types[R_REG_TYPE_LAST + 1] = {
	"gpr", "drx", "fpu", "mmx", "xmm", "ymm", "flg", "seg", NULL
};

// Take the 32bits name of a register, and return the 64 bit name of it.
// If there is no equivalent 64 bit register return NULL.
// SLOW
R_API const char *r_reg_32_to_64(RReg *reg, const char *rreg32) {
	int i, j = -1;
	RListIter *iter;
	RRegItem *item;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_list_foreach (reg->regset[i].regs, iter, item) {
			if (item->size == 32 && !r_str_casecmp (rreg32, item->name)) {
				j = item->offset;
				break;
			}
		}
	}
	if (j != -1) {
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
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
// SLOW
R_API const char *r_reg_64_to_32(RReg *reg, const char *rreg64) {
	int i, j = -1;
	RListIter *iter;
	RRegItem *item;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_list_foreach (reg->regset[i].regs, iter, item) {
			if (item->size == 64 && !r_str_casecmp (rreg64, item->name)) {
				j = item->offset;
				break;
			}
		}
	}
	if (j != -1) {
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
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

R_API const char *r_reg_get_name_by_type(RReg *reg, const char *alias_name) {
	const int n = r_reg_get_name_idx (alias_name);
	return (n != -1)? r_reg_get_name (reg, n): NULL;
}

R_API int r_reg_type_by_name(const char *str) {
	r_return_val_if_fail (str, -1);
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
	r_return_val_if_fail (type, -1);
	if (type[0] && type[1] && !type[2])
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

R_API bool r_reg_set_name(RReg *reg, int role, const char *name) {
	r_return_val_if_fail (reg && name, false);
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
	r_return_if_fail (reg);
	ut32 i;

	r_list_free (reg->roregs);
	reg->roregs = NULL;
	R_FREE (reg->reg_profile_str);
	R_FREE (reg->reg_profile_cmt);

	for (i = 0; i < R_REG_NAME_LAST; i++) {
		if (reg->name[i]) {
			R_FREE (reg->name[i]);
		}
	}
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		ht_pp_free (reg->regset[i].ht_regs);
		reg->regset[i].ht_regs = NULL;
		if (!reg->regset[i].pool) {
			continue;
		}
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
		reg->allregs = NULL;
	}
	reg->size = 0;
}

static int regcmp(RRegItem *a, RRegItem *b) {
	int offa = (a->offset * 16) + a->size;
	int offb = (b->offset * 16) + b->size;
	return (offa > offb) - (offa < offb);
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
	if (reg) {
		r_reg_free_internal (reg, false);
		free (reg);
	}
}

R_API RReg *r_reg_new(void) {
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

R_API bool r_reg_is_readonly(RReg *reg, RRegItem *item) {
	const char *name;
	RListIter *iter;
	if (!reg->roregs) {
		return false;
	}
	// XXX O(n)
	r_list_foreach (reg->roregs, iter, name) {
		if (!strcmp (item->name, name)) {
			return true;
		}
	}
	return false;
}

R_API ut64 r_reg_setv(RReg *reg, const char *name, ut64 val) {
	r_return_val_if_fail (reg && name, UT64_MAX);
	RRegItem *ri = r_reg_get (reg, name, -1);
	return ri? r_reg_set_value (reg, ri, val): UT64_MAX;
}

R_API ut64 r_reg_getv(RReg *reg, const char *name) {
	r_return_val_if_fail (reg && name, UT64_MAX);
	RRegItem *ri = r_reg_get (reg, name, -1);
	return ri? r_reg_get_value (reg, ri): UT64_MAX;
}

R_API RRegItem *r_reg_get(RReg *reg, const char *name, int type) {
	int i, e;
	r_return_val_if_fail (reg && name, NULL);
	//TODO: define flag register as R_REG_TYPE_FLG
	if (type == R_REG_TYPE_FLG) {
		type = R_REG_TYPE_GPR;
	}
	if (type == -1) {
		i = 0;
		e = R_REG_TYPE_LAST;
		int alias = r_reg_get_name_idx (name);
		if (alias != -1) {
			const char *nname = r_reg_get_name (reg, alias);
			if (nname) {
				name = nname;
			}
		}
	} else {
		i = type;
		e = type + 1;
	}
	for (; i < e; i++) {
		HtPP *pp = reg->regset[i].ht_regs;
		if (pp) {
			bool found = false;
			RRegItem *item = ht_pp_find (pp, name, &found);
			if (found) {
				return item;
			}
		}
	}
	return NULL;
}

R_API RList *r_reg_get_list(RReg *reg, int type) {
	if (type == R_REG_TYPE_ALL) {
		return reg->allregs;
	}

	RList *regs;
	int i, mask;
	if (type < 0 || type > (R_REG_TYPE_LAST - 1)) {
		return NULL;
	}

	regs = reg->regset[type].regs;
	if (r_list_length (regs) == 0) {
		mask = ((int)1 << type);
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			if (reg->regset[i].maskregstype & mask) {
				regs = reg->regset[i].regs;
			}
		}
	}

	return regs;
}

// TODO regsize is in bits, delta in bytes, maybe we should standarize this..
R_API RRegItem *r_reg_get_at(RReg *reg, int type, int regsize, int delta) {
	r_return_val_if_fail (reg, NULL);
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
	r_return_val_if_fail (reg && buf, NULL);
	if (type < 0 || type > (R_REG_TYPE_LAST - 1)) {
		return NULL;
	}
	RRegArena *arena = reg->regset[type].arena;
	int prev_offset = prev_ri ? (prev_ri->offset / 8) + (prev_ri->size / 8) : 0;
	RList *list = reg->regset[type].regs;
	RRegItem *ri;
	RListIter *iter;
	int offset;
	r_list_foreach (list, iter, ri) {
		offset = ri->offset / 8;
		if (offset > prev_offset) {
			if (memcmp (arena->bytes + offset, buf + offset, ri->size / 8)) {
				return ri;
			}
		}
	}
	return NULL;
}

R_API RRegSet *r_reg_regset_get(RReg *r, int type) {
	r_return_val_if_fail (r, NULL);
	if (type < 0 || type >= R_REG_TYPE_LAST) {
		return NULL;
	}
	RRegSet *rs = &r->regset[type];
	return rs->arena ? rs : NULL;
}
