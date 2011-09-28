/* radare - LGPL - Copyright 2009-2011 pancake<@nopcode.org> */

namespace Radare {
	[CCode (cname="R2_VERSION")]
	const string R2_VERSION;
#if 0
	[Compact]
	[CCode (cheader_filename="r_util.h", cprefix="r_hex_")]
	public static class Radare.RHex {
		//public static int str2bin (string input, uint8 *buf);
		//public static int hex_str2bin (string input, uint8 *buf);
		//public static int hex_bin2str (uint8 *buf, int len, out string str);
		//public static string hex_bin2strdup (uint8 *buf, int len);
		/* mem */
		//public static uint8 *mem_mem (uint8 *a, int al, uint8 *b, int bl);
		//public static void mem_copyendian (uint8 *dest, uint8 *orig, int size, int endian);
		//public static void mem_copyloop (uint8 *dest, uint8 *orig, int dsize, int osize);
		//public static void mem_cmp_mask (uint8 *dest, uint8 *orig, uint8 *mask, int len);
		/* num */
		//public static uint64 num_get(void *num, string str); // XXX void *
		//public static int offsetof(void *type, void *member);
	}
#endif

	[CCode (cheader_filename="r_util.h", lower_case_cprefix="r_str_", unref_function="")]
	namespace RStr {
		public static unowned string rwx_i (int rwx);
	//	public RStr(string arg);
		public static int hash(string str);
		public static int write(int fd, string str);
		public static int rwx(string str);
		public static void subchr(ref string str, int a, int b);
		//public static string @bool(bool b);
		public static int ansi_len(string str);
		public static int ansi_filter(ref string str, int len);
		//public static int writef(...);
	}

	[CCode (cheader_filename="r_util.h", lower_case_cprefix="r_file_")]
	namespace RFile {
		public static bool rm(string file);
		public static string tmpdir();
		public static string temp(string prefix);
		public static string slurp(string file, out int osz=null);
		public static string slurp_range(string file, uint64 off, int sz, out int osz=null);
		public static int dump(string file, uint8 *buf, int len);
		public static unowned string basename (string path);
		public static string abspath(string path);
		public static bool exist (string file);
		public static bool slurp_line (string file, int line, int ctx);
		
	}
	[CCode (cheader_filename="r_util.h", lower_case_cprefix="r_log_")]
	namespace RLog {
		public static void msg(string str);
		public static void error(string str);
		public static void file(string str);
		public static void progress(string str, int pc);
	}

	[CCode (cheader_filename="r_util.h", lower_case_cprefix="r_hex_", free_function="")]
	namespace RHex {
		public static int str2bin (string input, uint8 *buf);
		public static int bin2str (uint8 *buf, int len, out string str);
		public static string bin2strdup (uint8 *buf, int len);
	}

	[CCode (cheader_filename="r_util.h", lower_case_cprefix="r_sys_")]
	namespace RSystem {
		//public static const weak string OS;
		//public static const weak string ARCH;
		public static int sleep (int secs);
		public static int usleep (int usecs);
		public static string getenv (string key);
		public static bool setenv (string key, string val);
		//public static string cmd_str_full(string str, string input = "", out int len = null, out string sterr = null);
		public static int cmd (string command);
		//public static int cmdf (string command, ...);
		public static string cmd_str (string command, string? input=null, out int len=null);
		public static void backtrace();
	}

	[CCode (cname="RNum", cheader_filename="r_util.h", unref_function="", cprefix="r_num_", free_function="r_num_free")]
	public class RNum {
		public RNum(RNumCallback? cb=null, void *user=null);
		public uint64 get(string str);
		public uint64 math(string str);
	}
	[CCode (cname="RNumCallback", has_target="false")]
	public delegate uint64 RNumCallback (string str, int *ok);

	[Compact]
	[CCode (cname="RBuffer", cheader_filename="r_util.h", cprefix="r_buf_", free_function="r_buf_free")]
	public class RBuffer {
		public RBuffer();
		public uint8 *buf;
		public int read_at(uint64 addr, uint8 *buf, int len);
		public int write_at(uint64 addr, uint8 *buf, int len);
		public bool set_bytes(uint8 *buf, int len);
		//public bool memcpy(uint64 addr, uint8 *dst, uint8 *src, int len);
		// ..
	}
}

/* Generic Iterator interfaced with r_flist */
//[Compact] // XXX: Do not uncomment this...or generated vala code sucks and segfaults
[CCode (cprefix="r_flist_", cheader_filename="r_flist.h", cname="void*")]
public class RFList<G> {
	public RFList<G> iterator();
	public bool next();
	public unowned G @get();
}

//[Compact]
[CCode (cprefix="r_list_", cheader_filename="r_util.h", cname="RList")]
public class RList<G> {
	public void append(owned G foo);
	public void prepend(owned G foo);
	public RListIter<G> iterator();
	public RList();
	public uint length();
	public bool next();
	public unowned G @get();
	public bool del_n(int n);
	public bool get_top();
	public void push(owned G foo);
	public unowned G pop();
}

[Compact]
[CCode (cprefix="r_list_iter_", cheader_filename="r_list.h", cname="struct r_list_iter_t")]
public class RListIter<G> {
        public RListIter<G> n;
        public RListIter<G> p;
        public G data;

//	public G @free(G arg);
/*
	public bool next();
	public unowned G get();
*/

	[ReturnsModifiedPointer, CCode (cname = "_vala_r_list_iter_next")]
	public bool next() {
		return (bool)this.n;
	}
	[CCode (cname = "_vala_r_list_iter_get")]
	public G get () {
		return this.data;
	}
}

[Compact]
[CCode (cheader_filename="r_util.h", cname="struct r_range_t", free_function="r_range_free", cprefix="r_range_")]
public class Radare.RRange {
	/* lifecycle */
	public RRange();
	public RRange.from_string(string str);

	public Item *item_get(uint64 addr);
	public uint64 size();
	public uint64 add_from_string(string str);
	//public uint64 add_string(string str);
	//public uint64 add(uint64 fr, uint64 to, int rw);
//		public bool sub(uint64 fr, uint64 to);
	//public bool merge(Range r);
	public bool contains(uint64 addr);
	public bool sort();
	//public bool percent(); // XXX
	public bool list(bool rad); // XXX
	public bool get_n(int n, out uint64 fr, out uint64 to);
	public RRange *inverse(uint64 fr, uint64 to, int flags);

	[Compact]
	[CCode (cname="struct r_range_item_t", cprefix="r_range_item_")]
	public struct Item {
		public uint64 fr;
		public uint64 to;
		public uint8 *data;
		public int datalen;
	}
}
