/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_reg.h>
#include <r_util.h>

/* XXX: reg get can be accessed using the print_format stuff */
// This is the same as r_buf_set_bits, arenas can be r_buf
R_API ut64 r_reg_get_value(struct r_reg_t *reg, struct r_reg_item_t *item)
{
	struct r_reg_set_t *regset;
	ut32 v32;
	ut16 v16;
	ut8 v8;
	ut64 ret = 0LL;
	int off = BITS2BYTES(item->offset);
	regset = &reg->regset[item->type];
	if (item) {
		switch(item->size) {
		case 8:
			memcpy(&v8, regset->arena->bytes+off, 1);
			ret = v8;
			break;
		case 16:
			memcpy(&v16, regset->arena->bytes+off, 2);
			ret = v16;
			break;
		case 32:
			memcpy(&v32, regset->arena->bytes+off, 4);
			ret = v32;
			break;
		case 64:
			memcpy(&ret, regset->arena->bytes+off, 8);
			break;
		case 1:
			ret = (regset->arena->bytes[item->offset/8] & (1<<(item->offset%8)))?1:0;
			break;
		default:
			printf("get_value : TODO: implement bit level\n");
			break;
		}
	}
	return ret;
}

// TODO: cleanup this ugly code
R_API int r_reg_set_value(struct r_reg_t *reg, struct r_reg_item_t *item, ut64 value)
{
	ut64 v64;
	ut32 v32;
	ut16 v16;
	ut8 v8;
	ut8 *src;
	int ret = R_FALSE;
	if (item) {
		ret = R_TRUE;
		switch(item->size) {
		case 64: v64 = (ut64)value; src = (ut8*)&v64; break;
		case 32: v32 = (ut32)value; src = (ut8*)&v32; break;
		case 16: v16 = (ut16)value; src = (ut8*)&v16; break;
		case 8:  v8 = (ut8)value; src = (ut8*)&v8; break;
		case 1: 
			if (value) {
				ut8 * buf = reg->regset[item->type].arena->bytes + (item->offset/8);
				int bit = (item->offset%8);
				ut8 mask = (1<<bit);
				buf[0] = (buf[0] &(0xff^mask)) | mask;
			} else {
				ut8 * buf = reg->regset[item->type].arena->bytes + (item->offset/8);
				int bit = (item->offset%8);
				ut8 mask = 0xff^(1<<bit);
				buf[0] = (buf[0] & mask) | 0;
			}
			break;
		default: 
			printf("set_value : TODO: implement bit level\n");
			break;
		}
		r_mem_copybits(reg->regset[item->type].arena->bytes+BITS2BYTES(item->offset), src, item->size);
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
R_API ut64 r_reg_get_pvalue(struct r_reg_t *reg, struct r_reg_item_t *item, int packidx)
{
	return 0LL;
}

R_API int r_reg_set_pvalue(struct r_reg_t *reg, struct r_reg_item_t *item, ut64 value, int packidx)
{
	int ret = R_FALSE;
	return ret;
}
