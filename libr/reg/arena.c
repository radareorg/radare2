/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_reg.h>

/* non-endian safe - used for raw mapping with system registers */
R_API ut8* r_reg_get_bytes(RReg *reg, int type, int *size) {
	RRegArena *arena;
	int i, sz, osize;
	ut8 *buf;
	if (type == -1) {
		/* serialize ALL register types in a single buffer */
		// owned buffer is returned
		osize = sz = 0;
		buf = malloc (8);
		for (i=0; i<R_REG_TYPE_LAST; i++) {
			arena = reg->regset[i].arena;
			sz += arena->size;
			buf = realloc (buf, sz);
			if (!buf) break;
			memcpy (buf+osize, arena->bytes, arena->size);
			osize = sz;
		}
		if (size)
			*size = sz;
		return buf;
	}

	if (type<0 || type>R_REG_TYPE_LAST)
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
R_API int r_reg_set_bytes(RReg *reg, int type, const ut8* buf, int len) {
	int i, ret = R_FALSE;
	struct r_reg_set_t *regset;
	RRegArena *arena;
	int off = 0;
	if (len<0)
		return R_FALSE;

	if (type == -1) {
		ret = R_TRUE;
		/* deserialize ALL register types in a single buffer */
		for (i=0; i<R_REG_TYPE_LAST; i++) {
			if (!reg->regset[i].arena) {
				arena = reg->regset[i].arena = R_NEW (RRegArena);
				arena->size = len;
				arena->bytes = malloc (len);
			} else arena = reg->regset[i].arena;
			if (arena->bytes == NULL)
				return R_FALSE;
			memcpy (arena->bytes, buf+off, arena->size);
			off += arena->size;
			if (off>len) {
				ret = R_FALSE;
				break;
			}
		}
	} else {
		if (type>=0 && type<=R_REG_TYPE_LAST) {
			regset = &reg->regset[type];
			arena = regset->arena;
			if (len<1) return R_FALSE;
			if ((arena->size !=len ) || (arena->bytes == NULL)) {
				arena->size = len;
				arena->bytes = malloc (len);
			}
			if (arena->size != len) {
				arena->size = len;
			//	arena->bytes = malloc (len);
				regset->arena->bytes = realloc (regset->arena->bytes, len);
			}
			if (len > arena->size)
				len = arena->size;
			memset (arena->bytes, 0, arena->size);
			memcpy (arena->bytes, buf, len);
			ret = R_TRUE;
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
	int size, i;

	for (i=0; i<R_REG_TYPE_LAST; i++) {
		arena = reg->regset[i].arena;
		arena->size = 0;
		r_list_foreach (reg->regset[i].regs, iter, r) {
			size = BITS2BYTES (r->offset+r->size);
			if (size>arena->size) {
				arena->size = size;
				arena->bytes = realloc (arena->bytes, size);
				if (arena->bytes == NULL)
					return R_FALSE;
			}
		}
		memset (arena->bytes, 0, arena->size);
	}
	return R_TRUE;
}

R_API RRegArena *r_reg_arena_new (int size) {
	RRegArena *arena = R_NEW (RRegArena);
	if (arena) {
		if (size<1)
			size = 1;
		if (!(arena->bytes = malloc (size+8))) {
			free (arena);
			arena = NULL;
		} else arena->size = size;
	}
	return arena;
}

R_API void r_reg_arena_free(RRegArena* ra) {
	free (ra->bytes);
	free (ra);
}

R_API void r_reg_arena_swap(RReg *reg, int copy) {
	r_reg_arena_set (reg, (++reg->iters)%2, copy);
}

R_API int r_reg_arena_set(RReg *reg, int n, int copy) {
	int i;
	if (n>r_list_length (reg->regset[0].pool))
		return R_FALSE;
	for (i=0; i<R_REG_TYPE_LAST; i++) {
		RRegArena *o = reg->regset[i].arena;
		RRegArena *a = (RRegArena*)r_list_get_n (reg->regset[i].pool, n); 
		if (!a) continue;
		reg->regset[i].arena = a;
		if (a->size != o->size) {
			a->size = o->size;
			a->bytes = realloc (a->bytes, a->size+4);
			if (!a->bytes) {
				eprintf ("Cannot malloc %d in arena\n", a->size);
				// XXX This is critical!
				return R_FALSE;
			}
		}
		if (copy)
			r_reg_set_bytes (reg, i, o->bytes, a->size);
	}
	return R_TRUE;
}

R_API void r_reg_arena_pop(RReg *reg) {
	int i;
	for (i=0; i<R_REG_TYPE_LAST; i++) {
		if (r_list_length (reg->regset[i].pool)>0) {
			RRegArena *arena = r_list_pop (reg->regset[i].pool);
			//RRegArena *arena = (RRegArena*) r_list_head (reg->regset[i].pool);
			reg->regset[i].arena = arena;
		} else {
			eprintf ("Cannot pop more\n");
			break;
		}
	}
}

R_API int r_reg_arena_push(RReg *reg) {
	int i;
	for (i=0; i<R_REG_TYPE_LAST; i++) {
//eprintf ("PUSH %p\n", reg->regset[i].arena);
		r_list_push (reg->regset[i].pool, reg->regset[i].arena);
		if (!(reg->regset[i].arena = r_reg_arena_new (0)))
			return 0;
	}
	return r_list_length (reg->regset[0].pool);
}
