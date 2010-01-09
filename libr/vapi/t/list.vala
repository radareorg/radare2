/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

using Radare;

public class IterableObject {
	public string name { get; set; }

	public IterableObject(string name) {
		this.name = name;
	}
}

rList<IterableObject> get_list () {
	var list = new rList<IterableObject>();

	list.append (new IterableObject ("patata"));
	list.append (new IterableObject ("cacatua"));
	list.append (new IterableObject ("tutu"));
	list.append (new IterableObject ("baba"));

	return list;
}

void main() {
	var head = get_list ();
	foreach (var f in head) {
		stdout.printf(" - %p  %s\n", f, f.name);
	}
}
