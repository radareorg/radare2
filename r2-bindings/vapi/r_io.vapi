/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_io.h", cname="RIO", free_function="r_io_free", cprefix="r_io_")]
	public class RIO {
		public int fd;
		public bool cached;
		public bool cached_read;
		public bool enforce_rwx;
		public bool enforce_seek;
		public uint64 off;
		public bool debug;

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
		public uint64 va;

		public RIO();
		public RIO free();
		public bool set_write_mask(uint8 *buf, int len);

		//public uint64 off;
		/**
		 * Open a file using an uri specifying flags and mode
		 *
		 * uri: URI with path to file 
		 * flags: See Radare.Io.Flags
		 * mode: ...
		 */
		public RIO.Desc open(string uri, int flags, int mode);
		public RIO.Desc open_as(string urihandler, string path, int flags, int mode);
		public int redirect(string uri);
		public int set_fd(RIO.Desc fd);
		public int read(out uint8 *buf, int len);
		public int read_at(uint64 addr, uint8 *buf, int len);
		public RBuffer *read_buf(uint64 addr, int len);
		public int write(uint8 *buf, int len);
		public int write_at(uint64 addr, uint8 *buf, int len);
		public uint64 seek(uint64 addr, int whence);
		public int system(string cmd);
		public int close(RIO.Desc fd);
		public uint64 size();


		public void cache_commit ();
		public void cache_init ();
		public int cache_list (bool rad);
		public void cache_reset (bool set);
		public void cache_enable(bool rd, bool wr);
		public void cache_write(uint64 addr, ref uint8 *buf, int len);
		public void cache_read(uint64 addr, ref uint8 *buf, int len);

		/* undo */
		// TODO: Implement seek and write undo apis..they must be unified..
		public bool undo_init();
		public void undo_enable(bool set, bool write);

/*
		[Compact]
		[CCode(cname="RIOUndo")]
		public class Undo {
			bool s_enable;
			bool w_enable;
			bool w_init;
			int idx;
			int limit;
		}
*/
		//public uint64 undo_seek();
		//public void undo_redo();
		//public void undo_push();

		/* plugin */
		[Compact]
		[CCode (cname="RIOPlugin", cprefix="r_io_plugin_", free_function="")]
		public class Plugin {
			string name;
			string desc;
			// TODO: lot of missing stuff here :)
		}

		/* TODO: make them methods of Plugin class ? */
		public bool plugin_open(int fd, RIO.Plugin plugin);
		public bool plugin_close(int fd, RIO.Plugin plugin);
		public bool plugin_add(RIO.Plugin plugin);
		public int plugin_generate();
		public void plugin_list();

		/* maps */
		[CCode (cname="RIOMap", cprefix="r_io_map_", free_function="", unref_function="")]
		public class Map {
			int fd;
			int flags;
			uint64 delta;
			uint64 from;
			uint64 to;
		}
		public Map map_resolve(int fd);
		public bool map_add(int fd, int flags, uint64 delta, uint64 addr, uint64 size);
		public bool map_del(int fd);

		/* sections */
		[Compact]
		[CCode (cname="RIOSection", free_function="")]
		public class Section {
			string name;
			uint64 offset;
			uint64 vaddr;
			uint64 size;
			uint64 vsize;
			int rwx; // TODO: use perms
			int id;
		}

		public uint64 section_next(uint64 addr);
		public void section_list(uint64 addr, bool rad);
		public void section_list_visual(uint64 addr, uint64 len);
		public Section section_get(uint64 addr);
		public uint64 section_get_offset(uint64 addr);
		public uint64 section_get_vaddr(uint64 addr);
		public int section_get_rwx(uint64 addr);
		public bool section_overlaps(Section refsec);
		public uint64 section_vaddr_to_offset(uint64 vaddr);
		public uint64 section_offset_to_vaddr(uint64 offset);

		[Compact]
		[CCode (cname="RIODesc",free_function="")]
		public class Desc {
			public int fd;
			public int flags;
			public string name;
		}
		// int perms -> RIOPerm ?
		public void desc_add(RIO.Desc *desc);
		public bool desc_del(int fd);
		//public RIO.Desc desc_get (int fd);
		//public int desc_generate();
	}
}
