using Radare;

void main() {
	var reg = new RRegister();
	reg.set_profile_string (
		"gpr	eip	.32	0	0\n" +
		"gpr	eax	.32	4	0\n"
	);

	reg.set_value (reg.get ("eax"), 666);

/*
	KernelList<RRegister.Item*> head =
		reg.get_list (RRegister.Type.GPR);

	foreach (RRegister.Item* item in head) {
		print (" - %s (%d) = 0x%08"+uint64.FORMAT+"x\n",
			item->name, item->size,
			reg.get_value (item));
	}
*/

// XXX noarraylength vala bug
//	print ("%d\n", reg.types.length);
	for (int i=0;reg.get_type(i) != null; i++)
		print ("  Type %d is %s\n", i, reg.get_type (i));
}
