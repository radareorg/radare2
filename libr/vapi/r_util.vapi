/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

[CCode (cheader_filename="r_util.h", cprefix="r_util_", lower_case_cprefix="r_util_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_")]
	public static class Util {
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

	/* Generic Iterator interfaced with r_iter */
	//[Compact]
	[CCode (cprefix="r_iter_")]
	public class Iter<G> {
		public Iter (int size);
		public unowned G get ();
		public unowned G next ();
		public unowned G next_n (int idx);
		public unowned G prev ();
		public void delete ();
		public G first ();
		public bool last ();
		// TODO: foreach()
		public G free ();
		public void set (int idx, G data);
	}
}
