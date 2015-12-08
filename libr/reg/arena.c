/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_reg.h>

/* non-endian safe - used for raw mapping with system registers */
R_API ut8 *r_reg_get_bytes(RReg *reg, int type, int *size) {
	RRegArena *arena;
	int i, sz, osize;
	ut8 *buf, *newbuf;
	if (size) *size = 0;
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
		if (size) *size = sz;
		return buf;
	}
	if (type < 0 || type > (R_REG_TYPE_LAST - 1))
		return NULL;
	sz = reg->regset[type].arena->size;
	if (size)
		*size = sz;
	buf = malloc (sz);
	if (buf == NULL)
		return NULL;
	memcpy (buf, reg->regset[type].arena->bytes, sz);
	return buf;
}

/* reduce number of return statements */
R_API bool r_reg_set_bytes(RReg *reg, int type, const ut8 *buf, const int len) {
	int i, ret = false;
	struct r_reg_set_t *regset;
	RRegArena *arena;
	int off = 0;
	if (len < 0 || !buf)
		return false;

	if (type == -1) {
		ret = true;
		/* deserialize ALL register types in a single buffer */
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			if (reg->regset[i].arena) {
				arena = reg->regset[i].arena;
			} else {
				arena = reg->regset[i].arena = R_NEW (RRegArena);
				arena->size = len;
				arena->bytes = malloc (len);
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
				ret = false;
				break;
			}
		}
	} else {
		if (type >= 0 && type <= (R_REG_TYPE_LAST - 1)) {
			regset = &reg->regset[type];
			arena = regset->arena;
			if (len < 1) return false;
			if ((arena->size != len) || (arena->bytes == NULL)) {
				arena->bytes = malloc (len);
				if (!arena->bytes) {
					arena->size = 0;
					return false;
				}
				arena->size = len;
			}
			if (arena->size != len) {
				ut8 *buf = realloc (arena->bytes, len);
				if (buf) {
					arena->size = len;
					arena->bytes = buf;
				} else {
					eprintf ("Error resizing arena to %d\n", len);
					return false;
				}
			}
			if (arena->bytes) {
				memset (arena->bytes, 0, arena->size);
				//len = R_MIN (len, arena->size);
				memset (arena->bytes, 0, arena->size);
				memcpy (arena->bytes, buf, len);
				ret = true;
			} else ret = false;
		}
	}
	return ret;
}

#if 0
R_API int r_reg_arena_copy(RReg *reg, RRegArena *b) {
	RReg *
	RRegItem *r;
	RListIter *iter;
	int i, ret = R_FALSE;
	if (dst) {
		for(i=0;i<R_REG_TYPE_LAST;i++) {
			// TODO
		}
	}
	return ret;
}
#endif

R_API int r_reg_fit_arena(RReg *reg) {
	RRegArena *arena;
	RListIter *iter;
	RRegItem *r;
	int size, i, newsize;

	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		arena = reg->regset[i].arena;
		newsize = 0;
		r_list_foreach (reg->regset[i].regs, iter, r) {
			//int regsize_in_bytes = r->size / 8;
			// XXX: bits2bytes doesnt seems to work fine
			size = BITS2BYTES (r->offset + r->size);
			newsize = R_MAX (size, newsize);
		}
		if (newsize < 1) {
			free (arena->bytes);
			arena->bytes = NULL;
			arena->size = 0;
		} else {
			ut8 *buf = realloc (arena->bytes, newsize);
			if (!buf) {
				arena->bytes = NULL;
				arena->size = 0;
			} else {
				arena->size = newsize;
				arena->bytes = buf;
				memset (arena->bytes, 0, arena->size);
			}
		}
	}
	return true;
}

R_API RRegArena *r_reg_arena_new(int size) {
	RRegArena *arena = R_NEW (RRegArena);
	if (arena) {
		if (size < 1)
			size = 1;
		if (!(arena->bytes = malloc (size + 8))) {
			free (arena);
			arena = NULL;
		} else {
			arena->size = size;
			memset (arena->bytes, 0, size);
		}
	}
	return arena;
}

R_API void r_reg_arena_free(RRegArena *ra) {
	free (ra->bytes);
	free (ra);
}

R_API void r_reg_arena_swap(RReg *reg, int copy) {
	// XXX this api should be deprecated
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		if (r_list_length (reg->regset[i].pool) > 1) {
			RListIter *ia = reg->regset[i].pool->tail;
			RListIter *ib = reg->regset[i].pool->tail->p;
			void *tmp = ia->data;
			ia->data = ib->data;
			ib->data = tmp;
			reg->regset[i].arena = ia->data;
		} else {
			//eprintf ("Cannot pop more\n");
			break;
		}
	}
#if 0
	int index = (++reg->iters)%2;
	r_reg_arena_set (reg, index, copy);
#endif
}

R_API int r_reg_arena_set(RReg *reg, int n, int copy) {
	// XXX this api should be deprecated
	return false;
#if 0
	int i;
// XXX this shuoldnt be used at all
	if (n>r_list_length (reg->regset[0].pool)) {
		return R_FALSE;
	}
	for (i=0; i<R_REG_TYPE_LAST; i++) {
		RRegArena *o = reg->regset[i].arena;
		RRegArena *a = (RRegArena*)r_list_get_n (reg->regset[i].pool, n); 
		if (!a) {
			a = r_reg_arena_new (o->size);
			r_list_append (reg->regset[i].pool, a);
		}
		if (!a) continue;
		reg->regset[i].arena = a;
		if ((a->size != o->size) && (o->size>0)) {
			a->size = o->size;
			a->bytes = realloc (a->bytes, a->size+4);
			if (!a->bytes) {
				eprintf ("Cannot malloc %d in arena\n", a->size);
				// XXX This is critical!
				return R_FALSE;
			}
			memset (o->bytes, '\x00', o->size);
		}
		if (copy)
			r_reg_set_bytes (reg, i, o->bytes, a->size);
	}
	return true;
#endif
}

R_API void r_reg_arena_pop(RReg *reg) {
	RRegArena *a;
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		if (r_list_length (reg->regset[i].pool) < 2)
			continue;
		a = r_list_pop (reg->regset[i].pool);
		r_reg_arena_free (a);
		a = reg->regset[i].pool->tail->data;
		if (a) reg->regset[i].arena = a;
	}
}

R_API int r_reg_arena_push(RReg *reg) {
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = reg->regset[i].arena;      // current arena
		RRegArena *b = r_reg_arena_new (a->size); // new arena
		if (!a || !b) continue;
		// if (!i) {    r_print_hexdump (NULL, 0, a->bytes, a->size, 16, 16);    }
		memcpy (b->bytes, a->bytes, a->size);
		r_list_push (reg->regset[i].pool, b);
		reg->regset[i].arena = b;
	}
	return r_list_length (reg->regset[0].pool);
}

R_API void r_reg_arena_zero(RReg *reg) {
	int i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = reg->regset[i].arena;
		if (a->size > 0)
			memset (reg->regset[i].arena->bytes, 0, a->size);
	}
}

R_API ut8 *r_reg_arena_peek(RReg *reg) {
	RRegSet *regset = r_reg_regset_get (reg, R_REG_TYPE_GPR);
	if (!reg || !regset || !regset->arena || regset->arena->size < 1)
		return NULL;
	ut8 *ret = malloc (regset->arena->size);
	if (!ret) return NULL;
	memcpy (ret, regset->arena->bytes, regset->arena->size);
	return ret;
}

R_API void r_reg_arena_poke(RReg *reg, const ut8 *ret) {
	RRegSet *regset = r_reg_regset_get (reg, R_REG_TYPE_GPR);
	if (!ret || !regset || !regset->arena || !regset->arena->bytes)
		return;
	memcpy (regset->arena->bytes, ret, regset->arena->size);
}
