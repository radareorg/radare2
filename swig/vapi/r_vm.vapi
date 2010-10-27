/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

[CCode (cheader_filename="r_vm.h", cprefix="r_vm_", lower_case_cprefix="r_vm_")]
namespace Radare {
	[Compact]
	[CCode (cname="RVm", free_function="r_vm_free", cprefix="r_vm_")]
	public class RVm {
		public public RVm ();
		public bool log;
		public uint8* vm_stack;
		public RVm();
		public int print(int type);
		public int import(int in_vm);
		public int cpu_call(uint64 addr);
		public int set_arch(string name, int bits);
		public void reset();
		public int init(bool foo);
		public int cmd_eval(string cmd);
		public int eval_cmp(string cmd);
		public int eval_eq(string foo, string bar);
		public int eval_single(string foo);
		public int eval (string foo);
		public int eval_file (string file);
		public int emulate (int n);
		public int cmd_reg(string str);
		public int op_add(string op, string str);
		public int op_eval(string op);
		public int op_cmd(string op);

		public static void reg_type_list();
		public int reg_add(string name, int type, uint64 val););
		public uint64 reg_get(string name);
		public int reg_alias_list();
		public string reg_type(int type);
		public int reg_type_i(string str);
		public bool reg_del(string str);
		public bool reg_set(string str, uint64 val);
		public bool reg_alias(string name, string foo, string set);

		public void setup_flags(string zf);
		public void setup_cpu(string pc, string sp, string bp);
		public void setup_fastcall(string eax, strign ebx, string ecx, string edx);
		public void setup_ret(string eax);
		public void setup_push(uint64 val);
		public void setup_pop(string reg);

		public bool cmd_op(string op);
		public bool cmd_op_help();
		public bool op_list();
	}
}

