#include <r_reg.h>

void show_regs(struct r_reg_t *reg, int bitsize) {
	RList *reglist;
	RListIter *iter;
	RRegItem *ri;
	printf("%d bit registers:\n", bitsize);
	reglist = r_reg_get_list(reg, R_REG_TYPE_GPR);
	r_list_foreach (reglist, iter, ri) {
		if (ri->size == bitsize)
			printf(" - %s : 0x%08"PFMT64x"\n", ri->name, r_reg_get_value(reg, ri));
	}
}

int main() {
	int i;
	int foo[128];
	const char *type;
	struct r_reg_t *reg;

	for (i=0;i<128;i++)
		foo[i] = i;

	reg = r_reg_new ();
	r_reg_set_profile (reg, "../p/test.regs");
	r_reg_set_bytes (reg, -1, (const ut8 *)foo, sizeof(foo));
	show_regs (reg, 32);

	/* --- */
	r_reg_set_profile(reg, "../p/x86-linux.regs");
	printf ("Program counter is named: %s\n", r_reg_get_name (reg, R_REG_NAME_PC));
	show_regs (reg, 32);
	r_reg_set_value(reg, r_reg_get(reg, "eax", -1), 0x414141);
	r_reg_set_value(reg, r_reg_get(reg, "ecx", -1), 666);
	show_regs(reg, 32);
	r_reg_set_value(reg, r_reg_get(reg, "al", -1), 0x22);
	show_regs(reg, 33);

	r_reg_set_value(reg, r_reg_get(reg, "zero", -1), 0);
	show_regs(reg, 1);
	r_reg_set_value(reg, r_reg_get(reg, "zero", -1), 1);
	show_regs(reg, 1);

	for (i=0;(type=r_reg_get_type(i));i++)
		printf (" - %s\n", type);

	r_reg_arena_push(reg);
	r_reg_arena_pop(reg);

	r_reg_arena_push(reg);
	r_reg_arena_push(reg);
	r_reg_arena_push(reg);
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);
	r_reg_arena_push(reg);
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);

/*
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);
*/

	return 0;
}
