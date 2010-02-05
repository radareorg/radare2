/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_reg.h>
/* TODO: add push/pop.. */

/* non-endian safe - used for raw mapping with system registers */
R_API ut8* r_reg_get_bytes(struct r_reg_t *reg, int type, int *size)
{
	RRegisterArena *arena;
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
R_API int r_reg_set_bytes(struct r_reg_t *reg, int type, const ut8* buf, int len)
{
	int i, ret = R_FALSE;
	struct r_reg_set_t *regset;
	struct r_reg_arena_t *arena;
	int off = 0;

	if (type == -1) {
		ret = R_TRUE;
		/* deserialize ALL register types in a single buffer */
		for(i=0; i<R_REG_TYPE_LAST; i++) {
			arena = reg->regset[i].arena;
			if (arena == NULL) {
				arena = reg->regset[i].arena = R_NEW (RRegisterArena);
				arena->size = len;
				arena->bytes = malloc(len);
			}
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

R_API int r_reg_export_to(struct r_reg_t *reg, struct r_reg_t *dst)
{
	//struct r_reg_arena_t *arena;
	struct r_reg_item_t *r;
	struct list_head *pos;
	int i, ret = R_FALSE;
	if (dst) {
		// foreach reg of every time in reg, define it in dst
		for(i=0;i<R_REG_TYPE_LAST;i++) {
			list_for_each(pos, &reg->regset[i].regs) {
				r = list_entry(pos, struct r_reg_item_t, list);
				// TODO: export to not implemented
				//r_reg_set(dst, r_reg_get(dst, r->name), );
				//r_mem_copybits_delta(
			}
		}
	}
	return ret;
}

R_API int r_reg_fit_arena(struct r_reg_t *reg)
{
	struct list_head *pos;
	struct r_reg_item_t *r;
	struct r_reg_arena_t *arena;
	int size, i;

	/* propagate arenas */
	for(i=0;i<R_REG_TYPE_LAST;i++) {
		arena = reg->regset[i].arena;
		arena->size = 0;
		list_for_each(pos, &reg->regset[i].regs) {
			r = list_entry(pos, struct r_reg_item_t, list);
			size = BITS2BYTES(r->offset+r->size);
			if (size>arena->size) {
				arena->size = size;
				arena->bytes = realloc (arena->bytes, size);
				if (arena->bytes == NULL)
					return R_FALSE;
			}
		}
		memset(arena->bytes, 0, arena->size);
	}
	return R_TRUE;
}

R_API RRegisterArena *r_reg_arena_new (int size) {
	RRegisterArena *arena = R_NEW (RRegisterArena);
	if (arena) {
		if ((arena->bytes = malloc (size+8)) == NULL) {
			free (arena);
			arena = NULL;
		} else arena->size = size;
	}
	return arena;
}
