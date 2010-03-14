/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_io.h", cname="RIO", free_function="r_io_free", cprefix="r_io_")]
	public class RIO {
		[CCode (cprefix="R_IO_")]
		public enum Perm {
			READ = 0,
			WRITE = 1,
			EXEC = 2,
		}

		[CCode (cprefix="R_IO_SEEK_")]
		public enum Seek {
			SET = 0,
			CUR = 1,
			END = 2,
		}

		public RIO();
		public RIO free();
		public unowned RIO init();
		public bool set_write_mask(uint8 *buf, int len);

		//public uint64 off;
		/**
		 * Open a file using an uri specifying flags and mode
		 *
		 * uri: URI with path to file 
		 * flags: See Radare.Io.Flags
		 * mode: ...
		 */
		public int open(string uri, int flags, int mode);
		public int open_as(string urihandler, string path, int flags, int mode);
		public int read(out uint8 *buf, int len);
		public int read_at(uint64 addr, uint8 *buf, int len);
		public RBuffer *read_buf(uint64 addr, int len);
		public int write(uint8 *buf, int len);
		public uint64 seek(uint64 addr, int whence);
		public int system(string cmd);
		public int close(int fd);
		public uint64 size(int fd);


		/* undo */
		public void undo_enable(bool set, bool write);
		//public uint64 undo_seek();
		//public void undo_redo();
		//public void undo_push();

		/* handle */
		[Compact]
		[CCode (cname="RIOHandle", cprefix="r_io_handle_")]
		public class Handle {
			string name;
			string desc;
			// TODO: lot of missing stuff here :)
		}

		/* TODO: make them methods */
		public bool handle_open(int fd, Handle plugin);
		public bool handle_add(Handle plugin);
		//public int handle_generate();
		public void handle_list();

		/* maps */
		[CCode (cname="RIOMap", cprefix="r_io_map_")]
		public class Map {
			int fd;
			uint64 from;
			uint64 to;
		}
		public Map map_resolve(int fd);
		public bool map_add(int fd, int flags, uint64 delta, uint64 addr, uint64 size);
		public bool map_del(int fd);
		public void map_list(); // DEPRECATE
		public int map_read_at(uint64 addr, uint8 *buf, uint64 len);
		public int map_write_at(uint64 addr, uint8 *buf, uint64 len);

		/* sections */
		[CCode (cname="RIOSection")]
		public struct Section {
			string comment;
			uint64 from;
			uint64 to;
			uint64 vaddr;
			uint64 paddr;
			int rwx; // TODO: use perms
		}

		/* desc */
		[CCode (cname="RIODesc")]
		public struct Desc {
			int fd;
			int flags;
			const string name;
		}
		// int perms -> RIOPerm ?
		public bool desc_add(int fd, string file, int perms, Handle handle);
	}
}
