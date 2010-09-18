/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

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
			memcpy (buf+osize, arena->bytes, arena->size);
			osize += sz;
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

	if (type == -1) {
		ret = R_TRUE;
		/* deserialize ALL register types in a single buffer */
		for(i=0; i<R_REG_TYPE_LAST; i++) {
			if (!reg->regset[i].arena) {
				arena = reg->regset[i].arena = R_NEW (RRegArena);
				arena->size = len;
				arena->bytes = malloc(len);
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
			if (len<=regset->arena->size) {
				memcpy (regset->arena->bytes, buf, len);
				ret = R_TRUE;
			}
		}
	}
	return ret;
}

R_API int r_reg_export_to(RReg *reg, RReg *dst) {
	RRegItem *r;
	RListIter *iter;
	int i, ret = R_FALSE;
	if (dst) {
		// foreach reg of every time in reg, define it in dst
		for(i=0;i<R_REG_TYPE_LAST;i++) {
			r_list_foreach (reg->regset[i].regs, iter, r) {
				// TODO: export to not implemented
				//r_reg_set(dst, r_reg_get(dst, r->name), );
				//r_mem_copybits_delta(
			}
		}
	}
	return ret;
}

R_API int r_reg_fit_arena(RReg *reg) {
	RRegArena *arena;
	RListIter *iter;
	RRegItem *r;
	int size, i;

	/* propagate arenas */
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
