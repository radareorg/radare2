/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */


[Compact]
[CCode (cheader_filename="r_syscall.h", cname="struct r_syscall_t", free_function="r_syscall_free", cprefix="r_syscall_")]
public class Radare.RSyscall {

	[CCode (cprefix="R_SYSCALL_OS_")]
	public enum OS {
		LINUX = 0,
		NETBSD, OPENBSD, FREEBSD,
		DARWIN
	}

	[CCode (cprefix="R_SYSCALL_ARCH_")]
	public enum ARCH {
		X86 = 0, PPC, ARM, MIPS, SPARC
	}

	[CCode (cname="struct r_syscall_list_t", free_function="r_syscall_free")]
	public class List {
		string name;
		int swi;
		int num;
		int args;
		string sargs;
	}

	public RSyscall();
	public void setup(int os, int arch);
	public void setup_file(string file);
	public int get(string syscall);
	public unowned string get_i(int num, int swi);
	public unowned List get_n(int num);
	public void list();
}
