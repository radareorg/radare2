/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[Compact]
[CCode (cheader_filename="r_core.h", cname="struct r_core_t", free_function="r_core_free", cprefix="r_core_")]
public class Radare.RCore {
	/* lifecycle */
	public RCore();

	public static unowned RCore cast(uint64 ptr);
	public bool loadlibs();
	/* commands */
	public int prompt();
	//[CCode (PrintfFormat)]
	//public int cmdf(...);
	public int cmd(string cmd, bool log);
	public int cmd0(string cmd);
	/**
	 * Execute every line of the given file as radare commands
	 */
	public int cmd_file(string file);
	public int cmd_command(string cmd);
	public unowned string cmd_str(string cmd);

	/* io */
	public int read_at(uint64 addr, out uint8 *buf, int size);
	public int write_at(uint64 addr, uint8 *buf, int size);
	public int block_read(bool next);
	public int block_size(int size);
	public int seek(uint64 addr, bool rb);
	public int seek_align(uint64 addr, int count);

	/* files */
	public File file_open(string file, int mode);
	//public bool file_close_fd(int fd);

	// XXX mode = Radare.Io.Mode
	[Compact]
	[CCode (cname="struct r_core_file_t", cprefix="r_core_file_", free_function="")]
	public class File {
		//public static bool set(string file, Core.File file);
		//public static bool close(string file, Core.File file);
		/* attributes */
		public string uri;
		public string filename;
		public uint64 offset;
		public uint64 size;
		public int rwx;
		public int fd;
	}

	public File file;
}
