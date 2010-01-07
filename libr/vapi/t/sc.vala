using GLib;
using Radare; /* Radare.Hash */

public class SyscallExample
{
	public static void main(string[] args)
	{
		var sc = new rSyscall();
		sc.setup (rSyscall.ARCH.X86, rSyscall.OS.LINUX);
		print ("write = %d\n", sc.get("write"));
	}
}
