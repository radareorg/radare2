#include <r_reg.h>
#include <r_asm.h>


R_API struct r_reg_t *r_reg_init(struct r_reg_t *reg)
{
	if (reg) {
		reg->h = NULL;
		INIT_LIST_HEAD(&reg->handles);
	}
	return reg;
}

R_API struct r_reg_t *r_reg_new()
{
	struct r_reg_t *r = MALLOC_STRUCT(struct r_reg_t);
	return r_reg_init(r);
}

R_API struct r_reg_t *r_reg_free(struct r_reg_t *reg)
{
	if (reg) {
		// TODO: free more things here
		free(reg);
	}
	return NULL;
}

int r_reg_set_arch(struct r_reg_t *reg, int arch, int bits)
{
	int ret = R_FALSE;
	struct list_head *pos;
	list_for_each(pos, &reg->handles) {
		struct r_reg_handle_t *h = list_entry(pos, struct r_reg_handle_t, list);
		if (h->is_arch(arch, bits)) {
			reg->h = h;
			ret = R_TRUE;
			break;
		}
	}
	return ret;
}
