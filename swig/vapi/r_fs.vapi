/* radare2 - LGPL - Copyright 2011 pancake<nopcode.org> */

// TODO: Use nested classes instead of this wide class layout
namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_asm.h", cname="struct r_asm_t", free_function="r_asm_free", cprefix="r_asm_")]
	public class RFS {
		public RFS();
		public RFSRoot mount (string fstype, string path, uint64 delta);
		public bool umount (string path);
		public RFSRoot root (string path);
		public RFSFile open (string path);
		public void close (RFSFile file);
		public int read(RFSFile file, uint64 addr, int len);
		public RFSFile slurp(string path);
		public RList<RFSFile> dir(string path);
	}

	[Compact]
	public class RFSFile {
		public string name;
		public string path;
		public uint64 path;
		public uint32 size;
		public uint64 time;
		public void *ptr;
	}

	[Compact]
	public class RFSPlugin {
		public string name;
		public string desc;
	}

	[Compact]
	public class RFSRoot {
		public string path;
		public uint64 delta;
		public RFSPlugin p;
		public void *ptr;
	}
}
