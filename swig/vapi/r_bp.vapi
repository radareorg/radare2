/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

[Compact]
[CCode (cheader_filename="r_bp.h,r_list.h", cname="struct r_bp_t", free_function="r_bp_free", cprefix="r_bp_")]
public class Radare.RBreakpoint {
	public RBreakpoint ();
	public RList<Item> bps;
	public RList<Trace> traces;
	public bool use (string arch);
	public void enable (uint64 addr, bool enabled);
	public unowned Item? at_addr (uint64 addr, int rwx);
	public unowned Item add_sw (uint64 addr, int len, int rwx);
	public unowned Item add_hw (uint64 addr, int len, int rwx);
	public bool add_fault (uint64 addr, int len, int rwx);
	public int add_cond (string cond);
	public bool del (uint64 addr);
	public bool del_cond (int idx);

	/* TODO: deprecate the list() method.. language iterators should be enought */
	public int list (bool rad);

	[CCode (cprefix="R_BP_PROT_")]
	public enum Protection {
		READ,
		WRITE,
		EXEC
	}

	[CCode (cprefix="R_BP_TYPE_")]
	public enum Type {
		SW,
		HW,
		COND	
	}

	[Compact]
	[CCode (cname="RBreakpointItem", free_function="")]
	public class Item {
		uint64 addr;
		int size;
		int rwx;
		int hw;
		int trace;
		int enabled;
		uint8* obytes;
		uint8* bbytes;
		int[] pids;
	}

	[Compact]
	[CCode (cname="RBreakpointTrace", free_function="")]
	public class Trace {
		uint64 addr;
		uint64 addr_end;
		uint8 *traps;
		uint8 *buffer;
		uint8 *bits;
		int length;
		int bitlen;
	}
}
