/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

namespace Radare {
//[Compact]
//[CCode (cheader_filename="r_util.h", cprefix="r_util_")]
//public static class Radare.RUtil {
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
//}

#if FAILFAIL
	[CCode (cheader_filename="r_util.h", cprefix="r_str_")]
	public static class RStr {
		public RStr(string arg);
		public static int hash(string str);
	}

	[CCode (cheader_filename="r_util.h", cname="", cprefix="r_log_", free_function="")]
	public static class RLog {
		public static bool msg(string str);
		public static bool err(string str);
	}
#endif

	[CCode (cheader_filename="r_util.h", cprefix="r_sys_", free_function="")]
	public static class RSystem {
		public static int sleep (int secs);
		public static int usleep (int usecs);
		public static weak string getenv (string key);
		//public static string cmd_str_full(string str, string input = "", out int len = null, out string sterr = null);
		public static int cmd (string command);
		public static string cmd_str (string command, string? input, out int len=null);
	}

	[CCode (cheader_filename="r_util.h", cprefix="r_num_", free_function="")]
	public static class RNum {
		public RNum(RNumCallback cb, void *user);
		public uint64 get(string str);
		public uint64 math(string str);
	}
	[CCode (cname="RNumCallback")]
	public static delegate uint64 RNumCallback (string str, int *ok);

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

#if 0
/* TODO: to be removed. not fully compliant */
[Compact]
[CCode (cprefix="ralist_", cheader_filename="r_types.h,list.h", cname="struct list_head")]
public class KernelList<G> {
	public KernelList ();
	[CCode (cname="ralist_next")]
	public bool next();
	[CCode (cname="ralist_append")]
	public void append(owned G foo);
	[CCode (cname="")]
	public G @free(G arg);
	[CCode (cname="ralist_get", generic_type_pos=2)]
	public unowned G get();
	[CCode (cname="ralist_iterator")]
	public KernelList<G> iterator();
}
#endif

[Compact]
[CCode (cprefix="r_list_", cheader_filename="r_util.h", cname="struct r_list_t")]
public class RList<G> {
	public RList ();
	public void append(owned G foo);
	public void prepend(owned G foo);
	//public unowned G get();
	//public rListIter<G> iterator();
}

[Compact]
[CCode (cprefix="r_list_iter_", cheader_filename="r_list.h", cname="struct r_list_iter_t")]
public class RListIter<G> {
	public bool next();
//	public G @free(G arg);
	public unowned G get();
}

/* TODO: deprecated by r_iter ??? */
/*
[Compact]
[CCode (cprefix="rarray_", cheader_filename="r_types.h", cname="void")]
public static class rArray<G> {
	[CCode (cname="rarray_next", generic_type_pos=2)]
	public bool next(); //int type=0);
	[CCode (cname="")]
	public G @free(G arg);
	[CCode (cname="rarray_get", generic_type_pos=2)]
	public unowned G get(); //int type=0);
	[CCode (cname="rarray_iterator")] //, generic_type_pos=2)]
	public rArray<G> iterator();
}
*/
//}
