using Radare;

void main() {
	string code = """
print "Hello World\\n";
"""
;
	RLang lang = new RLang ();
	lang.use ("perl");
	lang.list ();
	lang.run (code, (int)code.length);
}
