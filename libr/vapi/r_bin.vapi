/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

[CCode (cheader_filename="r_bin.h", cprefix="r_bin_", lower_case_cprefix="r_bin_")]
namespace Radare {
	[Compact]
	[CCode (cname="RBin", free_function="r_bin_free", cprefix="r_bin_")]
	public class RBin {
		public const string file;
		public int size;

		public RBin();

		public int init();
		public int load(string file, string? plugin_name = null);
		public int list();
		public uint64 get_baddr();
		public RArray<RBin.Entry> get_entries();
		public RArray<RBin.Field*> get_fields();
		public RArray<RBin.Import*> get_imports();
		public RArray<RBin.Section*> get_sections();
		public RArray<RBin.String*> get_strings();
		public RArray<RBin.Symbol*> get_symbols();
		public RBin.Info* get_info();
	
		[CCode (cname="RBinEntry", free_function="", ref_function="", unref_function="")]
		public class Entry {
			public uint64 rva;
			public uint64 offset;
		}

		[CCode (cname="RBinSection", free_function="", ref_function="", unref_function="")]
		public class Section  {
			public string name;
			public int32 size;
			public int32 vsize;
			public int64 rva;
			public int64 offset;
			public int32 stringacteristics;
		}

		[CCode (cname="RBinSymbol", free_function="", ref_function="", unref_function="")]
		public class Symbol {
			public string name;
			public string forwarder;
			public string bind;
			public string type;
			public uint64 rva;
			public uint64 offset;
			public uint32 size;
			public uint32 ordinal;
		}

		[CCode (cname="RBinImport", free_function="", ref_function="", unref_function="")]
		public class Import {
			public string name;
			public string bind;
			public string type;
			public uint64 rva;
			public uint64 offset;
			public uint32 ordinal;
			public uint32 hint;
		}

		[CCode (cname="RBinInfo", free_function="", ref_function="", unref_function="")]
		public class Info {
			public string type;
			public string @class;
			public string rclass;
			public string arch;
			public string machine;
			public string os;
			public string subsystem;
			public int bigendian;
			public uint32 dbg_info;
		}

		[CCode (cname="RBinString", free_function="", ref_function="", unref_function="")]
		public class String {
			public string @string;
			public uint64 rva;
			public uint64 offset;
			public uint64 ordinal;
			public uint64 size;
		}

		[CCode (cname="RBinField", free_function="", ref_function="", unref_function="")]
		public class Field {
			public string name;
			public uint64 rva;
			public uint64 offset;
		}
	}
}
