using GLib;
using Radare; /* Radare.Hash */

public class SyscallExample
{
	public static void main(string[] args)
	{
		var sc = new RSyscall();
		sc.setup (RSyscall.ARCH.X86, RSyscall.OS.LINUX);
		print ("write = %d\n", sc.get("write"));
	}
}
