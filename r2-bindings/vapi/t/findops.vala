/*
  INT num: Interruptions. Typically used as antiemulation (INT 4) and antidebugging tricks (INT 3).
  UD2: Undefined instruction. Found in some packers/protectors as an antiemulation tricks.
  RDTSC: Widely used in malware to check if the software is being traced. A typical way to detect binary instrumentation (PIN, DynamoRIO, etc...).
  SIDT/SGDT: Store Interrupt/Global Descriptor Table. Trick used to detect some Virtual Machines (known as the red pill trick).
  CPUID: Used to detect Virtual Machines and emulators.
  // NOP args: NOP with arguments are typical antiemulation tricks.
  SYSENTER: Direct system calls. Commonly, used as antiemulation tricks.
*/

using RCore;

string[] opcodes = {
	"int",
	"sidt",
	"sgdt",
	"rdtsc",
	"cpuid",
	"ud2",
	"sysenter",
};

public static void entry(RCore core) {
	var addr = core.num.get ("entry0");
	for (;;) {
		var op = core.disassemble (addr);
		if (op == null)
			break;
		var txt = op.get_asm ();
		foreach (var str in opcodes) {
			if (txt.index_of (str) != -1) {
				print (@"$addr: $txt\n");
			}
		}
		addr += op.inst_len;
	}
}

public static void main() {
	entry (null);
}
