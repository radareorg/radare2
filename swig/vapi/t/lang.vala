using Radare;

void main() {
	string code = """
print "Hello World\\n";
"""
;
	Language lang = new Language();
	lang.use("perl");
	lang.list();
	lang.run(code, (int)code.length);
}
