uses
	Radare.Search

init
	var s = new Searcher(Mode.KEYWORD)
	s.kw_add("lib", "")
	s.begin()

	var str = "foo is pure lib"
	s.update_i(0, str, str.len())
