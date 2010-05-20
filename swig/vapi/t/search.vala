/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

using Radare;

public class SearchExample
{
	public static void main(string[] args)
	{
		string buf = "liblubliuamlibfoo";
		var s = new RSearch (RSearch.Mode.KEYWORD);
		s.kw_add (new RSearch.Keyword.str ("lib", "", ""));
		s.set_callback (
			(kw, user, addr) => {
				stdout.printf("Hit %d! at 0x%"+uint64.FORMAT+
					"\n", (int)kw.count, addr);
				return 0;
			}, null);
		s.begin ();

		print ("string: \"%s\"\n", buf);
		print ("search: \"%s\"\n", "lib");
		print ("length: %ld\n", buf.len());
		s.update_i(0LL, (uint8*)buf, buf.len());
		s = null;
	}
}
