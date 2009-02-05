/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_io.h", cprefix="r_io", lower_case_cprefix="r_io_")]
namespace Radare
{
	class Io {
		public static bool init();
		public static bool set_write_mask(int fd, uint8 *buf, int len);
		public static int open(string uri, int flags, int mode);
		public static int read(int fd, out uint8 *buf, int len);
		public static int write(int fd, uint8 *buf, int len);
		public static uint64 lseek(int fd, u64 addr, int whence);
		public static int system(int fd, string cmd);
		public static int close(int fd);
		public static u64 size(int fd);
	}

	[Compact]
	[CCode (cprefix="r_io_handle_")]
	public struct Handle {
		public static bool init();
		
	}

	[Compact]
	[CCode (cprefix="r_io_map_")]
	public struct Map {
		public static bool init();
		
	}
}
