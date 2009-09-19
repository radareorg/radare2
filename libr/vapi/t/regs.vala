using Radare;

void main() {

	Register reg = new Register();

	reg.set_profile_string("""
gpr	eip	.32	0	0
gpr	eax	.32	4	0
"""
);
	reg.set_value(reg.get("eax"), 666);

	Radare.List<Register.Item*> head =
		reg.get_list(Register.Type.GPR);

	foreach(Register.Item* item in head) {
		stdout.printf(" - %s (%d) = 0x%08llx\n",
			item->name, item->size,
			reg.get_value(item));
	}
}
