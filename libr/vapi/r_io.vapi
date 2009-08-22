/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_io.h", cprefix="r_io", lower_case_cprefix="r_io_")]
namespace Radare
{
	[Compact]
	[CCode (cname="struct r_io_t", free_function="r_io_free", cprefix="r_io_")]
	public class Io {
		public Io();
		public Io* free();
		public bool init();
		public bool set_write_mask(int fd, uint8 *buf, int len);
		public int open(string uri, int flags, int mode);
		public int read(int fd, out uint8 *buf, int len);
		public int write(int fd, uint8 *buf, int len);
		public uint64 lseek(int fd, ut64 addr, int whence);
		public int system(int fd, string cmd);
		public int close(int fd);
		public ut64 size(int fd);
	}

	//[Compact]
	[CCode (cprefix="r_io_handle_")]
	public struct Handle {
		public static bool init();
		
	}

	//[Compact]
	[CCode (cprefix="r_io_map_")]
	public struct Map {
		public static bool init();
	}
}
