#include <r_reg.h>

void show_regs(struct r_reg_t *reg, int bitsize) {
	RList *reglist;
	RListIter *iter;
	RRegItem *ri;
	printf("%d bit registers:\n", bitsize);
	reglist = r_reg_get_list(reg, bitsize==1?
		R_REG_TYPE_FLG: R_REG_TYPE_GPR);
	r_list_foreach (reglist, iter, ri) {
		if (ri->size == bitsize)
			printf(" - %s : 0x%08"PFMT64x"\n", ri->name, r_reg_get_value(reg, ri));
	}
}

void print_eflags_bits (RReg *reg) {
	int a;
	a = r_reg_getv (reg, "cf"); printf (" c:%d", a);
printf (" 1");
	a = r_reg_getv (reg, "pf"); printf (" p:%d", a);
printf (" 0");
	a = r_reg_getv (reg, "af"); printf (" a:%d", a);
printf (" 0");
	a = r_reg_getv (reg, "zf"); printf (" z:%d", a);
	a = r_reg_getv (reg, "sf"); printf (" s:%d", a);
	a = r_reg_getv (reg, "tf"); printf (" t:%d", a);
	a = r_reg_getv (reg, "if"); printf (" i:%d", a);
	a = r_reg_getv (reg, "df"); printf (" d:%d", a);
	a = r_reg_getv (reg, "of"); printf (" o:%d", a);
	printf ("\n");
}

int main() {
	int i;
	int foo[128];
	const char *type;
	struct r_reg_t *reg;

	for (i=0;i<128;i++)
		foo[i] = i;

	reg = r_reg_new ();
	r_reg_set_profile (reg, "./test.regs");
	r_reg_set_bytes (reg, -1, (const ut8 *)foo, sizeof(foo));
{
	ut64 a;
	RRegItem *item;
	item = r_reg_get (reg, "eflags", R_REG_TYPE_GPR);
	r_reg_set_value (reg, item, 0x00000346); //0xffffffffffff);
	a = r_reg_get_value (reg, item);
	eprintf ("A32 = 0x%x\n", (int)a);
	if ((int)a != -1) {
		eprintf ("1 FAIL\n");
	}

print_eflags_bits (reg);
	item = r_reg_get (reg, "zf", R_REG_TYPE_GPR);
	a = r_reg_get_value (reg, item);
	eprintf ("A = %d\n", (int)a);
	if (a != 1) {
		eprintf ("2 FAIL\n");
	}

	item = r_reg_get (reg, "zf", R_REG_TYPE_GPR);
	r_reg_set_value (reg, item, 1);
	a = r_reg_get_value (reg, item);
	eprintf ("A = %d\n", (int)a);
	if (a != 1) {
		eprintf ("3 FAIL\n");
	}
	r_reg_set_value (reg, item, 0);
	a = r_reg_get_value (reg, item);
	eprintf ("A = %d\n", (int)a);
	if (a != 0) {
		eprintf ("4 FAIL\n");
	}
}
	show_regs (reg, 1); //32);

exit (0);
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

	r_reg_set_value (reg, r_reg_get (reg, "zero", -1), 0);
	show_regs (reg, 1);
	r_reg_set_value (reg, r_reg_get (reg, "zero", -1), 1);
	show_regs (reg, 1);

	for (i=0; (type=r_reg_get_type (i));i++)
		printf (" - %s\n", type);

	r_reg_arena_push (reg);
	r_reg_arena_pop (reg);

	r_reg_arena_push (reg);
	r_reg_arena_push (reg);
	r_reg_arena_push (reg);
	r_reg_arena_pop (reg);
	r_reg_arena_pop (reg);
	r_reg_arena_push (reg);
	r_reg_arena_pop (reg);
	r_reg_arena_pop (reg);
/*
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);
	r_reg_arena_pop(reg);
*/
	return 0;
}
