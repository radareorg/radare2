[CCode (cheader_filename="r_config.h", cprefix="r_", lower_case_cprefix="r_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_config_", cname="RConfig", free_function="r_config_free")]
	public class RConfig {
		//TODO: public void setup_file(string file);
		public bool lock;
		public int last_notfound;
		public int n_nodes;

		//public void @lock (bool enable);
		public int eval(string str);

		public unowned string get(string name);
		public uint64 get_i(string name);

		public RConfigNode node_get (string name);
		public static RConfigNode node_new (string name, string val);

		public unowned string desc (string name, string? desc);
		public int swap (string name);
		public RConfigNode set(string name, string val);
		public RConfigNode set_i(string name, uint64 val);

		public void list(string? foo, bool rad);
	}

	[CCode (cname="RConfigNode", free_function="", unref_function="")]
	public class RConfigNode {
		string name;
		int hash;
		int flags;
		string @value;
		uint64 i_value;
		/* TODO: moar */
	}

	[CCode (cname="int", cprefix="CN_")]
	public enum RConfigNodeType {
		BOOL,
		INT,
		OFFT,
		STR,
		RO,
		RW,
	}
}
