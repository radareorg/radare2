/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

[CCode (cheader_filename="r_bp.h", cprefix="r_bp", lower_case_cprefix="r_bp_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_bp_t", free_function="r_bp_free", cprefix="r_bp_")]
	public class rBreakpoint {
		public rBreakpoint();
		public void enable(uint64 addr, bool enabled);
		public bool at_addr(uint64 addr, int rwx);
		public Item add_sw(uint64 addr, int len, int rwx);
		public Item add_hw(uint64 addr, int len, int rwx);
		public bool add_fault(uint64 addr, int len, int rwx);
		public int add_cond(string cond);
		public bool del(uint64 addr);
		public bool del_cond(int idx);
		public int list(int rad);

		[CCode (cprefic="R_BP")]
		public enum Protection {
			READ,
			WRITE,
			EXEC
		}

		[CCode (cprefic="R_BP_TYPE")]
		public enum Type {
			SW,
			HW,
			COND	
		}

		[Compact]
		[CCode (cname="struct r_bp_item_t", cprefix="r_bp_item")]
		public struct Item {
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
	}
}
