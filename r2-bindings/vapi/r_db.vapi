/* radare - LGPL - Copyright 2009-2011 pancake<@nopcode.org> */

namespace Radare {
	[Compact]
	[CCode (cheader_filename="r_db.h", cname="struct r_db_t", free_function="r_db_free", cprefix="r_db_")]
	public class RDatabase {
		/* lifecycle */
		public RDatabase();
		public void free();

		/* storage */
		public int add_id(int off, int size);
		public bool @add(void *b);
		public bool add_unique(void *b);
		public bool delete(void *b);
		public void* get(int key, uint8* buf);

		/* stacky! */
	//	public int push(ref uint8* buf);
	//	public uint8 *pop();
	}
	[Compact]
	[CCode (cheader_filename="r_db.h", cname="struct r_pair_t", free_function="r_pair_free", cprefix="r_pair_")]
	public class RPair {
		/* lifecycle */
		public RPair();
		public RPair.from_file(string file);
		public void free();

		/* storage */
		public void delete(string k);
		public string get(string k);
		public void set (string k, string v);
		//TODO public RList<RPairItem> list (string domain);
		public void sync();
		public void reset();
	}
}
