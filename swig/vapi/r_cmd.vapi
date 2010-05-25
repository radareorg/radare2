/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

namespace Radare {
	// HACK
	[Compact]
	[CCode (cheader_filename="r_lib.h", cprefix="r_lib_struct_", cname="struct r_lib_struct_t", free_function="", destroy_function="")]
	public struct RCmdStruct {
		public RLibType type;
		public RCmdPlugin data;
	}

	[Compact]
	[CCode (cheader_filename="r_cmd.h", cprefix="r_cmd_", cname="struct r_cmd_macro_t", free_function="")]
	public class RCmdMacroItem {
		int counter;
		// TODO much moar
	}

	[CCode (has_target=false, cname="RCmdCallback")]
	public delegate bool RCmdCallback (void *user, string cmd);

	[CCode (cheader_filename="r_cmd.h", cname="RCmdPlugin", free_function="", destroy_function="")]
	public struct RCmdPlugin {
		string name;
		RCmdCallback call;
	}

	[Compact]
	[CCode (cheader_filename="r_cmd.h", cprefix="r_cmd_", cname="struct r_cmd_t", free_function="r_cmd_free")]
	public class RCmd {
		public RCmd ();
		public void set_data (void *data);
		public bool @add (string cmd, string desc, RCmdCallback cb);
		public bool add_long (string cmd, string scmd, string desc);
		public bool del (string cmd);
		public bool call (string cmd);
		public bool call_long (string cmd);
	}
}
