/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

[CCode (cheader_filename="r_db.h", cprefix="r_db_", lower_case_cprefix="r_db_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_db_t", free_function="r_db_free", cprefix="r_db_")]
	public class Database {
		/* lifecycle */
		public Database();
		public void init();
		public void free();

		/* storage */
		public int add_id(int off, int size);
		public bool @add(void *b);
		public bool delete(void *b);
		public void* get(int key, uint8* buf);

		/* stacky! */
		public int push(ref uint8* buf);
		public uint8 *pop();
	}
}
