[CCode (cheader_filename="r_config.h", cprefix="r_", lower_case_cprefix="r_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_config_t", free_function="r_config_free")]
	public class Config {
		public void setup(int os, int arch);
		public void setup_file(string file);

		public int eval(string str);

		public int get(string name);
		public string get_i(string name);

		public string set(string name, string val);
		public string set_i(string name, string val);

		public void list();
	}
}
