/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */


[Compact]
[CCode (cheader_filename="r_syscall.h", cname="struct r_syscall_t", free_function="r_syscall_free", cprefix="r_syscall_")]
public class Radare.RSyscall {
	[CCode (cname="struct r_syscall_item_t", free_function="")]
	public class Item {
		string name;
		int swi;
		int num;
		int args;
		string sargs;
	}

	public RSyscall();
	public void setup(string arch, string os);
	public void setup_file(string file);
	public unowned Item get(int num, int swi);
	public int get_num(string str);
	public unowned Item get_n(int num);
	public unowned string get_i(int num, int swi);
	public void list();
}
