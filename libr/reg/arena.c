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
