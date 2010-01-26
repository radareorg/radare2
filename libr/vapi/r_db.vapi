/* radare - LGPL - Copyright 2009-2010 pancake<@nopcode.org> */

[Compact]
[CCode (cheader_filename="r_db.h", cname="struct r_db_t", free_function="r_db_free", cprefix="r_db_")]
public class Radare.RDatabase {
	/* lifecycle */
	public RDatabase();
	/**
	* Initializes a database object
	*/
	public void init();
	public void free();

	/* storage */
	public int add_id(int off, int size);
	public bool @add(void *b);
	public bool add_unique(void *b);
	public bool delete(void *b);
	public void* get(int key, uint8* buf);

	/* stacky! */
	public int push(ref uint8* buf);
	public uint8 *pop();
}
