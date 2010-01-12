/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_core.h", cprefix="r_core", lower_case_cprefix="r_core_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_core_t", free_function="r_core_free", cprefix="r_core_")]
	public class rCore {
		/* lifecycle */
		public rCore();

		/* commands */
		public int prompt();
		public int cmd(string cmd, bool log);
		public int cmd0(string cmd);
		public int cmd_file(string file);
		public unowned string cmd_str(string cmd);

		/* io */
		public int read_at(uint64 addr, out uint8 *buf, int size);
		public int write_at(uint64 addr, uint8 *buf, int size);
		public int block_read(bool next);
		public int seek(uint64 addr, bool rb);

		/* files */
		public rCore.File file_open(string file, int mode);

		// XXX mode = Radare.Io.Mode
		[Compact]
		[CCode (cname="struct r_core_file_t", cprefix="r_core_")]
		public class File {
			//public static bool set(string file, Core.File file);
			//public static bool close(string file, Core.File file);
			public static bool close_fd(string file, int fd);
			/* attributes */
			public string uri;
			public string filename;
			public uint64 offset;
			public uint64 size;
			public int rwx;
			public int fd;
		}
	}
}
