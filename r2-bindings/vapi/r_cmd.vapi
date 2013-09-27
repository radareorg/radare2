/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

namespace Radare {
/*
	// HACK
	[Compact]
	[CCode (cheader_filename="r_lib.h", cprefix="r_cmd_struct_", cname="RCmdStruct", free_function="", destroy_function="")]
	public struct RCmdStruct {
		public RLibType type;
		public RCmdPlugin *data;
	}

	[Compact]
	[CCode (cheader_filename="r_cmd.h", cprefix="r_cmd_macro_", cname="RCmdMacro", free_function="")]
	public class RCmdMacro {
		int counter;
		uint64 *brk_value;
		uint64 _brk_value;
		int brk;
		// TODO much moar
		public int @add (string name);
		public int rm (string name);
		public void list ();
		public int call (string name);
		public int @break (string val);
	}


	[CCode (cheader_filename="r_cmd.h", cname="RCmdPlugin", free_function="", destroy_function="")]
	public struct RCmdPlugin {
		string name;
		string desc;
		RCmdCallback call;
	}
*/

	[Compact]
	[CCode (cheader_filename="r_cmd.h", cprefix="r_cmd_", cname="RCmd", free_function="r_cmd_free")]
	public class RCmd {
		[CCode (has_target=false, cname="RCmdCallback")]
		public delegate bool Callback (void *user, string cmd);
		public RCmd ();
		public void set_data (void *data);
		public bool @add (string cmd, string desc, Callback cb);
		public bool add_long (string cmd, string scmd, string desc);
		public bool del (string cmd);
		public bool call (string cmd);
		public bool call_long (string cmd);
	}
}
