/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */

[Compact]
[CCode (cheader_filename="r_magic.h", cname="RMagic", free_function="r_magic_free", cprefix="r_magic_")]
public class Radare.RMagic {
	/* lifecycle */
	public RMagic(int flags=0);

	public weak string file(string f);
	public weak string descriptor(int d);
	public weak string buffer(void *buffer, size_t n);

	public int load(string file);
	public int check(string file);
	public int compile(string file);
	public void setflags(int flags);
}

