/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

[CCode (cheader_filename="r_util.h", cprefix="r_util_", lower_case_cprefix="r_util_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_")]
	public static class rUtil {
		public static int hex_str2bin (string input, uint8 *buf);
		//public static int hex_bin2str (uint8 *buf, int len, out string str);
		public static string hex_bin2strdup (uint8 *buf, int len);
		/* mem */
		public static uint8 *mem_mem (uint8 *a, int al, uint8 *b, int bl);
		public static void mem_copyendian (uint8 *dest, uint8 *orig, int size, int endian);
		public static void mem_copyloop (uint8 *dest, uint8 *orig, int dsize, int osize);
		public static void mem_cmp_mask (uint8 *dest, uint8 *orig, uint8 *mask, int len);
		/* num */
		public static uint64 num_get(void *num, string str); // XXX void *
		//public static int offsetof(void *type, void *member);
	}

	// ???
	[CCode (cprefix="r_str")]
	public static class rStr {
		public rStr();
		public int hash(string str);
	}

	[CCode (cprefix="r_num")]
	public static class rNum {
		public rNum();
		public uint64 get(string str);
		public uint64 math(string str);
	}

	[CCode (cprefix="r_log")]
	public static class rLog {
		public bool msg(string str);
		public bool err(string str);
	}

	[CCode (cprefix="r_buf_")]
	public class rBuffer {
		public rBuffer();
		public int read_at(uint64 addr, uint8 *buf, int len);
		public int write_at(uint64 addr, uint8 *buf, int len);
		public bool set_bytes(uint8 *buf, int len);
		public bool memcpy(uint64 addr, uint8 *dst, uint8 *src, int len);
		/* ... */
	}

	/* Generic Iterator interfaced with r_iter */
        [Compact]
        [CCode (cprefix="r_iter_", cname="void*")]
        public class rIter<G> {
                public rIter (int size);
                public unowned G cur ();
                public bool next ();
                public void rewind ();
		public unowned G get ();
                public unowned rIter<G> get_n (int idx);
                public unowned G prev ();
                public void delete ();
                public unowned G first ();
		public void @foreach (rIterCallback cb);
                public unowned G free ();
                public void set (int idx, owned G data);
		public rIter<G> iterator ();
		/* defining the callback here results in signature of:
			static gint __lambda1__void*r_iter_callback (IterableObject* foo, gpointer self) {
			                           ^---- wtf!
			iter.vala:55.23-55.28: error: The name `name' does not exist in the context of `G'
			public delegate int rIterCallback (G foo);
		*/
        }
	public delegate int rIterCallback (void * foo);

	[Compact]
	[CCode (cprefix="ralist_", cheader_filename="list.h", cname="struct list_head")]
	public static class rList<G> {
		[CCode (cname="ralist_next")]
		public bool next();
		[CCode (cname="")]
		public G @free(G arg);
		[CCode (cname="ralist_get", generic_type_pos=2)]
		public unowned G get(); //int type=0);
		[CCode (cname="ralist_iterator")]
		public rList<unowned G> iterator();
	}

/*
	[Compact]
	[CCode (cprefix="rarray_", cheader_filename="r_types.h", cname="rarray_t")]
	public static struct RarrayFoo<G> {
		[CCode (cname="rarray_next", generic_type_pos=2)]
		public bool next();
		[CCode (cname="")]
		public G @free(G arg);
		[CCode (cname="rarray_get", generic_type_pos=2)]
		public unowned G get();
		[CCode (cname="rarray_iterator")] //, generic_type_pos=2)]
		public RarrayFoo<G> iterator();
	}
*/

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
}
