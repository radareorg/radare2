/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <r_reg.h>
#include <r_util/r_str.h>

/* non-endian safe - used for raw mapping with system registers */
R_API ut8 *r_reg_get_bytes(RReg *reg, int type, int *size) {
	RRegArena *arena;
	int i, sz, osize;
	ut8 *buf, *newbuf;
	if (size) {
		*size = 0;
	}
	if (type == -1) {
		/* serialize ALL register types in a single buffer */
		// owned buffer is returned
		osize = sz = 0;
		buf = malloc (8);
		if (!buf) {
			return NULL;
		}
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			arena = reg->regset[i].arena;
			sz += arena->size;
			newbuf = realloc (buf, sz);
			if (!newbuf) {
				break;
			}
			buf = newbuf;
			memcpy (buf + osize, arena->bytes, arena->size);
			osize = sz;
		}
		if (size) {
			*size = sz;
		}
		return buf;
	}
	if (type < 0 || type > (R_REG_TYPE_LAST - 1)) {
		return NULL;
	}
	sz = reg->regset[type].arena->size;
	if (size) {
		*size = sz;
	}
	if (!sz) {
		return NULL;
	}
	buf = malloc (sz);
	if (buf) {
		memcpy (buf, reg->regset[type].arena->bytes, sz);
	}
	return buf;
}

/* deserialize ALL register types into buffer */
/* XXX does the same as r_reg_get_bytes? */
R_API bool r_reg_read_regs(RReg *reg, ut8 *buf, const int len) {
	int i, off = 0;
	RRegArena *arena;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		if (reg->regset[i].arena) {
			arena = reg->regset[i].arena;
		} else {
			arena = reg->regset[i].arena = R_NEW0 (RRegArena);
			if (!arena) {
				return false;
			}
			arena->size = len;
			arena->bytes = calloc (1, len);
			if (!arena->bytes) {
				r_reg_arena_free (arena);
				return false;
			}
		}
		if (!arena->bytes) {
			arena->size = 0;
			return false;
		}
		memset (arena->bytes, 0, arena->size);
		memcpy (arena->bytes, buf + off,
			R_MIN (len - off, arena->size));
		off += arena->size;
		if (off > len) {
			return false;
		}
	}
	return true;
}

/* TODO reduce number of return statements */
R_API bool r_reg_set_bytes(RReg *reg, int type, const ut8 *buf, const int len) {
	int maxsz, minsz;
	struct r_reg_set_t *regset;
	RRegArena *arena;
	if (len < 1 || !buf) {
		return false;
	}
	if (type < 0 || type >= R_REG_TYPE_LAST) {
		return false;
	}
	regset = &reg->regset[type];
	arena = regset->arena;
	if (!arena) {
		return false;
	}
	maxsz = R_MAX (arena->size, len);
	minsz = R_MIN (arena->size, len);
	if ((arena->size != len) || (!arena->bytes)) {
		free (arena->bytes);
		arena->bytes = calloc (1, maxsz);
		if (!arena->bytes) {
			arena->size = 0;
			return false;
		}
		arena->size = maxsz;
	}
	if (arena->size != maxsz) {
		ut8 *tmp = realloc (arena->bytes, maxsz);
		if (!tmp) {
			eprintf ("Error resizing arena to %d\n", len);
			return false;
		}
		arena->size = maxsz;
		arena->bytes = tmp;
	}
	if (arena->bytes) {
		memset (arena->bytes, 0, arena->size);
		memcpy (arena->bytes, buf, minsz);
		return true;
	}
	return false;
}

R_API int r_reg_fit_arena(RReg *reg) {
	RRegArena *arena;
	RListIter *iter;
	RRegItem *r;
	int size, i, newsize;

	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		arena = reg->regset[i].arena;
		if (!arena) {
			continue;
		}
		newsize = 0;
		r_list_foreach (reg->regset[i].regs, iter, r) {
			// XXX: bits2bytes doesnt seems to work fine
			size = BITS2BYTES (r->offset + r->size);
			newsize = R_MAX (size, newsize);
		}
		if (newsize < 1) {
			R_FREE (arena->bytes);
			arena->size = 0;
		} else {
			ut8 *buf = realloc (arena->bytes, newsize);
			if (buf) {
				arena->size = newsize;
				arena->bytes = buf;
				memset (arena->bytes, 0, arena->size);
			} else {
				arena->bytes = NULL;
				arena->size = 0;
			}
		}
	}
	return true;
}

R_API RRegArena *r_reg_arena_new(int size) {
	RRegArena *arena = R_NEW0 (RRegArena);
	if (arena) {
		if (size < 1) {
			size = 1;
		}
		if (!(arena->bytes = calloc (1, size + 8))) {
			R_FREE (arena);
		} else {
			arena->size = size;
		}
	}
	return arena;
}

R_API void r_reg_arena_free(RRegArena *ra) {
	if (ra) {
		free (ra->bytes);
		free (ra);
	}
}

R_API void r_reg_arena_swap(RReg *reg, int copy) {
	/* XXX: swap current arena to head(previous arena) */
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		if (!reg->regset[i].pool) {
			continue;
		}
		if (r_list_length (reg->regset[i].pool) > 1) {
			RListIter *ia = reg->regset[i].cur;
			RListIter *ib = reg->regset[i].pool->head;
			void *tmp = ia->data;
			ia->data = ib->data;
			ib->data = tmp;
			reg->regset[i].arena = ia->data;
		} else {
			break;
		}
	}
}

R_API void r_reg_arena_pop(RReg *reg) {
	RRegArena *a;
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		if (!reg->regset[i].pool) {
			continue;
		}
		if (r_list_length (reg->regset[i].pool) < 2) {
			continue;
		}
		a = r_list_pop (reg->regset[i].pool);
		r_reg_arena_free (a);
		a = reg->regset[i].pool->tail->data;
		if (a) {
			reg->regset[i].arena = a;
			reg->regset[i].cur = reg->regset[i].pool->tail;
		}
	}
}

R_API int r_reg_arena_push(RReg *reg) {
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = reg->regset[i].arena; // current arena
		if (!a) {
			continue;
		}
		RRegArena *b = r_reg_arena_new (a->size); // new arena
		if (!b) {
			continue;
		}
		//b->size == a->size always because of how r_reg_arena_new behave
		if (a->bytes) {
			memcpy (b->bytes, a->bytes, b->size);
		}
		r_list_push (reg->regset[i].pool, b);
		reg->regset[i].arena = b;
		reg->regset[i].cur = reg->regset[i].pool->tail;
	}
	if (reg->regset[0].pool) {
		return r_list_length (reg->regset[0].pool);
	}
	return 0;
}

R_API void r_reg_arena_zero(RReg *reg) {
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = reg->regset[i].arena;
		if (a->size > 0) {
			memset (reg->regset[i].arena->bytes, 0, a->size);
		}
	}
}

R_API ut8 *r_reg_arena_peek(RReg *reg) {
	RRegSet *regset = r_reg_regset_get (reg, R_REG_TYPE_GPR);
	if (!reg || !regset || !regset->arena || (regset->arena->size < 1)) {
		return NULL;
	}
	ut8 *ret = malloc (regset->arena->size);
	if (!ret) {
		return NULL;
	}
	memcpy (ret, regset->arena->bytes, regset->arena->size);
	return ret;
}

R_API void r_reg_arena_poke(RReg *reg, const ut8 *ret) {
	RRegSet *regset = r_reg_regset_get (reg, R_REG_TYPE_GPR);
	if (!ret || !regset || !regset->arena || !regset->arena->bytes) {
		return;
	}
	memcpy (regset->arena->bytes, ret, regset->arena->size);
}

R_API ut8 *r_reg_arena_dup(RReg *reg, const ut8 *source) {
	RRegSet *regset = r_reg_regset_get (reg, R_REG_TYPE_GPR);
	if (!reg || !regset || !regset->arena || (regset->arena->size < 1)) {
		return NULL;
	}
	ut8 *ret = malloc (regset->arena->size);
	if (!ret) {
		return NULL;
	}
	memcpy (ret, source, regset->arena->size);
	return ret;
}

R_API int r_reg_arena_set_bytes(RReg *reg, const char *str) {
	str = r_str_trim_head_ro (str);
	int len = r_hex_str_is_valid (str);
	if (len == -1) {
		eprintf ("Invalid input\n");
		return -1;
	}
	int bin_str_len = (len + 1) / 2; //2 hex chrs for 1 byte
	ut8 *bin_str = malloc (bin_str_len);
	if (!bin_str) {
		eprintf ("Failed to decode hex str.\n");
		return -1;
	}
	r_hex_str2bin (str, bin_str);

	int i, n = 0; //n - cumulative sum of arena's sizes
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		int sz = reg->regset[i].arena->size;
		int bl = bin_str_len - n; //bytes left
		int bln = bl - n;
		if (bln > 0 && bln < sz) {
			r_reg_set_bytes (reg, i, bin_str + n, bln);
			break;
		}
		r_reg_set_bytes (reg, i, bin_str + n, bin_str_len - n);
		n += sz;
	}
	free (bin_str);
	return 0;
}

R_API void r_reg_arena_shrink(RReg *reg) {
	RListIter *iter;
	RRegArena *a;
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_list_foreach (reg->regset[i].pool, iter, a) {
			free (a->bytes);
			/* ha ha ha */
			a->bytes = calloc (1024, 1);
			a->size = 1024;
			/* looks like sizing down the arena breaks the regsync */
			/* and sizing it up fixes reallocation when fit() is called */
		}
	}
}
