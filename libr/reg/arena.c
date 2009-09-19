/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_reg.h>
/* TODO: add push/pop.. */

/* non-endian safe - used for raw mapping with system registers */
R_API ut8* r_reg_get_bytes(struct r_reg_t *reg, int type, int *size)
{
	if (type == -1) {
		/* serialize ALL register types in a single buffer */
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
	int ret = R_FALSE;
	struct r_reg_set_t *regset;

	if (type == -1) {
		/* deserialize ALL register types in a single buffer */
	} else {
		if (type >= 0 && type <= R_REG_TYPE_LAST) {
			regset = &reg->regset[type];
			if (len <= regset->arena->size) {
				memcpy(regset->arena->bytes, buf, len);
				ret = R_TRUE;
			}
		}
	}
	return ret;
}

R_API int r_reg_export_to(struct r_reg_t *reg, struct r_reg_t *dst)
{
	int ret = R_FALSE;
	if (dst) {
		// foreach reg of every time in reg, define it in dst
	}
	return ret;
}

R_API void r_reg_arena_fit(struct r_reg_t *reg)
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
