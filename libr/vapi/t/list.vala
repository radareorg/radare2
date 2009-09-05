/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

using Radare;

[Import]
[CCode (cname="get_list")]
public static extern Radare.List<Foo> get_list();

void main() {
	Radare.List<Foo> head = get_list();
	foreach (Foo f in head) {
		stdout.printf(" - %p  %s\n", f, f.name);
	}
}
