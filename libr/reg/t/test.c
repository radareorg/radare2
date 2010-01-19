#include <r_reg.h>

void show_regs(struct r_reg_t *reg, int bitsize)
{
	struct list_head *pos, *reglist;
	printf("%d bit registers:\n", bitsize);
	reglist = r_reg_get_list(reg, R_REG_TYPE_GPR);
	list_for_each(pos, reglist) {
		struct r_reg_item_t *ri = list_entry(pos, struct r_reg_item_t, list);
		if (ri->size == bitsize)
			printf(" - %s : 0x%08llx\n", ri->name, r_reg_get_value(reg, ri));
	}
}

int main() {
	int i;
	struct r_reg_t *reg;

	reg = r_reg_new();
	r_reg_set_profile(reg, "../p/x86-linux.regs");

	show_regs(reg, 32);
	r_reg_set_value(reg, r_reg_get(reg, "eax", -1), 0x414141);
	r_reg_set_value(reg, r_reg_get(reg, "ecx", -1), 666);
	show_regs(reg, 32);
	r_reg_set_value(reg, r_reg_get(reg, "al", -1), 0x22);
	show_regs(reg, 32);

	r_reg_set_value(reg, r_reg_get(reg, "zero", -1), 0);
	show_regs(reg, 1);
	r_reg_set_value(reg, r_reg_get(reg, "zero", -1), 1);
	show_regs(reg, 1);

	for (i=0;r_reg_types[i];i++)
		printf (" - %s\n", r_reg_types[i]);

	return 0;
}
