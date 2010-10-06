using Radare;

public static void main(string[] args)
{
	var c = new RCore();
	c.file_open("/bin/ls", 0);
	foreach (var a in c.asm_bwdisassemble(0x67c0, 4, 64))
		print("BACKWARD DISASM: 0x%08"+uint64.FORMAT_MODIFIER+"x\n", a.addr);
}
