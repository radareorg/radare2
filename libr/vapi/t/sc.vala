using GLib;
using Radare; /* Radare.Hash */

public class SyscallExample
{
	public static void main(string[] args)
	{
		Syscall sc = new Syscall();
		sc.setup(Syscall.ARCH.X86, Syscall.OS.LINUX);
		stdout.printf("write = %d\n", sc.get("write"));
	}
}
