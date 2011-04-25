/* radare2 - LGPL - Copyright 2011 pancake<nopcode.org> */

// TODO: Use nested classes instead of this wide class layout
namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_fs.h", cname="struct r_fs_t", free_function="r_fs_free", cprefix="r_fs_")]
	public class RFS {
		public RFS();
		public unowned RFSRoot? mount (string fstype, string path, uint64 delta);
		public bool umount (string path);
		public RFSRoot root (string path);
		public RFSFile open (string path);
		public void close (RFSFile file);
		public int read(RFSFile file, uint64 addr, int len);
		public RFSFile slurp(string path);
		public RList<RFSFile> dir(string path);
		public RList<RFSPartition> partitions (string ptype, uint64 delta);
		public RList<RFSRoot> roots;
	}

	[Compact]
	[CCode (cheader_filename="r_fs.h", cname="struct r_fs_file_t", free_function="r_fs_file_free", cprefix="r_fs_file_")]
	public class RFSFile {
		public string name;
		public string path;
		public uint64 off;
		public uint32 size;
		public uint8 *data;
		public void *ctx;
		public char type;
		public uint64 time;
		public RFSPlugin p;
		public RFSRoot root;
		public void *ptr;
	}

	[Compact]
	[CCode (cheader_filename="r_fs.h", cname="struct r_fs_plugin_t", free_function="r_fs_plugin_free", cprefix="r_fs_plugin_")]
	public class RFSPlugin {
		public string name;
		public string desc;
	}

	[Compact]
	[CCode (cheader_filename="r_fs.h", cname="struct r_fs_root_t", free_function="r_fs_root_free", cprefix="r_fs_root_")]
	public class RFSRoot {
		public string path;
		public uint64 delta;
		public RFSPlugin p;
		public void *ptr;
	}

	[Compact]
	[CCode (cheader_filename="r_fs.h", cname="struct r_fs_partition_t", free_function="r_fs_partition_free", cprefix="r_fs_partition_")]
	public class RFSPartition {
		public int number;
		public uint64 start;
		public uint64 length;
		public int index;
		public int type;
	}
}
