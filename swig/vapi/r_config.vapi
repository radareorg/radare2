[CCode (cheader_filename="r_config.h", cprefix="r_", lower_case_cprefix="r_")]
namespace Radare {
	[Compact]
	[CCode (cprefix="r_config_", cname="struct r_config_t", free_function="r_config_free")]
	public class RConfig {
		//TODO: public void setup_file(string file);

		public int eval(string str);

		public weak string get(string name);
		public uint64 get_i(string name);

		public RConfigNode set(string name, string val);
		public RConfigNode set_i(string name, uint64 val);

		public void list(string? foo, int bar);
	}

	[CCode (cname="RConfigNode", free_function="")]
	public class RConfigNode {
		string name;
		int hash;
		int flags;
		string @value;
		uint64 i_value;
		/* TODO: moar */
	}
}
