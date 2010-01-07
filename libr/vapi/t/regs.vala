using Radare;

void main() {
	var reg = new rRegister();
	reg.set_profile_string (
		"gpr	eip	.32	0	0\n" +
		"gpr	eax	.32	4	0\n"
	);

	reg.set_value (reg.get ("eax"), 666);

	rList<rRegister.Item*> head =
		reg.get_list (rRegister.Type.GPR);

	foreach (rRegister.Item* item in head) {
		print (" - %s (%d) = 0x%08llx\n",
			item->name, item->size,
			reg.get_value (item));
	}
}
