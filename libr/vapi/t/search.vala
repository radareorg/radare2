/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

using Radare.Search;

public class SearchExample
{
	public static void main(string[] args)
	{
		string buf = "liblubliuamlibfoo";
		var s = new Searcher(Mode.KEYWORD);
		s.kw_add("lib", "");
		s.set_callback(
			(kw, user, addr) => {
				stdout.printf("Hit %d! at 0x%llx\n", (int)kw.count, addr);
				return 0;
			}, null);
		s.begin();

		stdout.printf("string: \"%s\"\n", buf);
		stdout.printf("search: \"%s\"\n", "lib");
		stdout.printf("length: %ld\n", buf.len());
		s.update_i(0LL, (uint8*)buf, buf.len());
		s = null;
	}
}
