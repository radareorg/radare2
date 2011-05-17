uses
	Radare

init
	var s = new RSearch (RSearch.Mode.KEYWORD)
	var k = new RSearch.Keyword.str ("lib", "", "")
	s.kw_add (k)
	s.begin ()

	var str = "foo is pure lib"
	s.update_i (0, str, str.length)
