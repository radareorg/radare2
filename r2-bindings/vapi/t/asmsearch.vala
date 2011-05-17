using Radare;

public static void main(string[] args)
{
	var c = new RCore();
	var b = new RBin();
	c.file_open("/bin/ls", 0);
	b.load("/bin/ls", false);
	uint64 baddr = b.get_baddr();
	foreach (var scn in b.get_sections())
		if ((scn.srwx & 0x1) != 0)
				foreach (var hit in c.asm_strsearch("jmp e; ret", scn.offset, scn.offset+scn.size))
					print("0x%08"+uint64.FORMAT_MODIFIER+"x - %s\n", baddr+hit.addr, hit.code);
}
