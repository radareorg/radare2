/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

[Compact]
[CCode (cheader_filename="r_print.h", cprefix="r_print_", cname="struct r_print_t", free_function="r_print_free")]
public class Radare.RPrint {
	public RPrint();
	public string hexpair (string str, int idx);
	public void set_flags (int flags);
	public void set_width (int width);
	public void hexdump(uint64 addr, uint8* buf, int len, int baddr, int step);
	public void hexpairs(uint64 addr, uint8 *buf, int len);
	public void bytes(uint8* buf, int len, string fmt);
	//public void @byte (string fmt, int idx, uint8 ch);
	public void c(uint8 *buf, int len);
	public void raw(uint8 *buf, int len);
	public void cursor(int cur, int set);
	public void set_cursor(int curset, int ocursor, int cursor);
	public void code(uint64 addr, uint8* buf, int len);
	//public void string(uint64 addr, uint8* buf, int len);
	public int date_dos(uint8* buf, int len);
	public int date_w32(uint8* buf, int len);
	public int date_unix(uint8* buf, int len);
}
