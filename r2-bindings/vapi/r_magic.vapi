/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_magic.h", cname="RMagic", free_function="r_magic_free", cprefix="r_magic_")]
	public class RMagic {
		public RMagic(int flags);

		public unowned string file(string f);
		public unowned string descriptor(int d);
		public unowned string buffer(void *buffer, int n);

		public int load(string file);
		public int check(string file);
		public int compile(string file);
		public void setflags(int flags);
	}
}
