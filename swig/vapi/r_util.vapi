/* radare - LGPL - Copyright 2009-2010 pancake<@nopcode.org> */

namespace Radare {
[Compact]
[CCode (cheader_filename="r_util.h", cprefix="r_")]
public static class Radare.RHex {
	public static int str2bin (string input, uint8 *buf);
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

#if FAILFAIL
	[CCode (cheader_filename="r_util.h", cprefix="r_str_")]
	public static class RStr {
		public RStr(string arg);
		public static int hash(string str);
		public static int write(int fd, string str);
		//public static int writef(...);
	}

	[CCode (cheader_filename="r_util.h", cname="", cprefix="r_log_", free_function="")]
	public static class RLog {
		public static bool msg(string str);
		public static bool err(string str);
	}
#endif

	[CCode (cheader_filename="r_util.h", cprefix="r_hex_", free_function="")]
	public static class RHex {
		public static int str2bin (string input, uint8 *buf);
		public static int bin2str (uint8 *buf, int len, out string str);
		public static string bin2strdup (uint8 *buf, int len);
	}

	[CCode (cheader_filename="r_util.h", cprefix="r_sys_", free_function="")]
	public static class RSystem {
		//public static const weak string OS;
		//public static const weak string ARCH;
		public static int sleep (int secs);
		public static int usleep (int usecs);
		public static unowned string getenv (string key);
		//public static string cmd_str_full(string str, string input = "", out int len = null, out string sterr = null);
		public static int cmd (string command);
		public static string cmd_str (string command, string? input, out int len=null);
	}

	[CCode (cname="RNum", cheader_filename="r_util.h", cprefix="r_num_", free_function="")]
	public static class RNum {
		public RNum(RNumCallback cb, void *user);
		public uint64 get(string str);
		public uint64 math(string str);
	}
	[CCode (cname="RNumCallback", has_target="false")]
	public delegate uint64 RNumCallback (string str, int *ok);

	[Compact]
	[CCode (cname="RBuffer", cheader_filename="r_util.h", cprefix="r_buf_", free_function="r_buf_free")]
	public static class RBuffer {
		public RBuffer();
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
}

//[Compact]
[CCode (cprefix="r_list_iter_", cheader_filename="r_list.h", cname="struct r_list_iter_t")]
public class RListIter<G> {
	public bool next();
//	public G @free(G arg);
	public unowned G get();
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
	public static struct Item {
		public uint64 fr;
		public uint64 to;
		public uint8 *data;
		public int datalen;
	}
}
