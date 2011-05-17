// XXX: only required for list.vala (must be removed)
// DEMO TEST DEMO TEST DEMO TEST DEMO TEST DEMO TEST //
[Compact]
[CCode (cname="struct foo", cheader_filename="list_c.h")]
public class Foo {
	public string name;
	[CCode (cname="")]
	public void free();
}
