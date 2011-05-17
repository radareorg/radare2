/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_bin.h,r_list.h,r_types_base.h", cname="struct r_bin_t", free_function="r_bin_free", cprefix="r_bin_")]
	public class RBin {
		[CCode (cprefix="R_BIN_SYM_")]
		public enum Sym {
			ENTRY,
			INIT,
			MAIN,
			FINI,
			LAST
		}
		public const string file;
		public int narch;
		public RBin.Arch curarch;

		public RBin();

		public uint64 wr_scn_resize (string name, uint64 size);
		public int wr_rpath_del ();
		public int wr_output (string filename);

		public int load(string file, bool dummy);
		public int set_arch(string arch, int bits, string name);
		public int set_archidx(int idx);
		public int list();
		public uint64 get_baddr();
		public RBin.Addr get_sym(int sym); // XXX: use RBin.Sym here ?
		public RList<RBin.Addr> get_entries();
		public RList<RBin.Field> get_fields();
		public RList<RBin.Import> get_imports();
		public RList<RBin.Section> get_sections();
		public RList<RBin.String> get_strings();
		public RList<RBin.Symbol> get_symbols();
		public RList<RBin.Reloc> get_relocs();
		public RList<string> get_libs();
		public RBin.Info get_info();
		public int is_big_endian();
		public int is_stripped();
		public int is_static();
		public int has_dbg_linenums();
		public int has_dbg_syms();
		public int has_dbg_relocs();
		public int meta_get_line(uint64 addr, ref string file, int len, out int line);
		public string meta_get_source_line(uint64 addr);
	
		[CCode (cname="RBinArch", free_function="", ref_function="", unref_function="")]
		public struct Arch {
			public unowned string file;
			public int size;
			public RBuffer buf;
		}

		[CCode (cname="RBinAddr", free_function="", ref_function="", unref_function="")]
		public class Addr {
			public uint64 rva;
			public uint64 offset;
		}

		[CCode (cname="RBinSection", free_function="", ref_function="", unref_function="")]
		public class Section {
			public string name;
			public int32 size;
			public int32 vsize;
			public uint64 rva;
			public uint64 offset;
			public int32 srwx;
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

		[CCode (cname="RBinReloc", free_function="", ref_function="", unref_function="")]
		public class Reloc {
			public string name;
			public uint64 rva;
			public uint64 offset;
			public uint32 sym;
			public uint32 type;
		}

		[CCode (cname="RBinInfo", free_function="", ref_function="", unref_function="")]
		public class Info {
			public string file;
			public string type;
			public string @class;
			public string rclass;
			public string arch;
			public string machine;
			public string os;
			public string subsystem;
			public int bits;
			public bool big_endian;
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
