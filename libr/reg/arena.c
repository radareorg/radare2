/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_reg.h>
/* TODO: add push/pop.. */

/* non-endian safe - used for raw mapping with system registers */
R_API ut8* r_reg_get_bytes(struct r_reg_t *reg, int type, int *size)
{
	struct r_reg_arena_t *arena;
	int sz, osize = 0;
	int i;
	if (type == -1) {
		/* serialize ALL register types in a single buffer */
		// owned buffer is returned
		ut8 * buf = malloc(1);
		for(i=0;i<R_REG_TYPE_LAST;i++) {
			arena = reg->regset[type].arena;
			sz += arena->size;
			buf = realloc(buf, sz);
			memcpy(buf+osize, arena->bytes, arena->size);
			osize = sz;
		}
		if (size)
			*size = sz;
		return buf;
	}

	if (type < 0 || type > R_REG_TYPE_LAST)
		return NULL;
	if (size)
		*size = reg->regset[type].arena->size;
	return reg->regset[type].arena->bytes;
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
		for(i=0;i<R_REG_TYPE_LAST;i++) {
			arena = reg->regset[type].arena;
			if (arena == NULL) {
				arena = reg->regset[i].arena = MALLOC_STRUCT(struct r_reg_arena_t);
				arena->size = len;
				arena->bytes = malloc(len);
			}
			memcpy(arena->bytes, buf+off, arena->size);
			off += arena->size;
			if (off>len) {
				ret = R_FALSE;
				break;
			}
		}
	} else {
		if (type >= 0 && type <= R_REG_TYPE_LAST) {
			regset = &reg->regset[type];
			if (len <= regset->arena->size) {
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
				//r_reg_set(dst, r_reg_get(dst, r->name), );
				//r_mem_copybits_delta(
			}
		}
	}
	return ret;
}

R_API void r_reg_fit_arena(struct r_reg_t *reg)
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
				arena->bytes = realloc(arena->bytes, size);
			}
		}
		memset(arena->bytes, 0, arena->size);
	}
}
