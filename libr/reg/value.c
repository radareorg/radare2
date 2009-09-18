/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_reg.h>

/* XXX: reg get can be accessed using the print_format stuff */
R_API ut64 r_reg_get_value(struct r_reg_t *reg, struct r_reg_item_t *item)
{
	struct r_reg_set_t *regset;
	ut64 ret = 0LL;
	regset = &reg->regset[item->type];
	if (item) {
		switch(item->size) {
		case 1:
			ret = (regset->arena->bytes[item->offset] & 0xff);
			break;
		case 2:
			break;
		case 8:
			break;
		}
	}
	return ret;
}

R_API int r_reg_set_value(struct r_reg_t *reg, struct r_reg_item_t *item, ut64 value)
{
	int ret = R_FALSE;
	if (item) {
		ret = R_TRUE;
	}
	return ret;
}

/* floating point */
// XXX: use double for better precission?
R_API float r_reg_get_fvalue(struct r_reg_t *reg, struct r_reg_item_t *item)
{
	return 0.0;
}

R_API int r_reg_set_fvalue(struct r_reg_t *reg, struct r_reg_item_t *item, float value)
{
	int ret = R_FALSE;
	return ret;
}

/* packed registers */
R_API ut64 r_reg_get_pvalue(struct r_reg_t *reg, struct r_reg_item_t *item, ut64 value, int packidx)
{
	return 0LL;
}

R_API int r_reg_set_pvalue(struct r_reg_t *reg, struct r_reg_item_t *item, ut64 value, int packidx)
{
	int ret = R_FALSE;
	return ret;
}
