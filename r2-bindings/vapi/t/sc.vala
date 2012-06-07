using GLib;
using Radare; /* Radare.Hash */

public class SyscallExample
{
	public static void main(string[] args)
	{
		var sc = new RSyscall();
		sc.setup ("x86", "linux", 32);
		print ("write = %d\n", sc.get_num("write"));
	}
}
