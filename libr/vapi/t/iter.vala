/* radare - LGPL - Copyright 2009-2010 pancake<@nopcode.org> */

using Radare;

public class IterableObject {
	public string name { get; set; }

	public IterableObject(string name) {
		this.name = name;
	}
}

rIter<IterableObject> get_iter_list () {
	rIter<IterableObject> list = new rIter<IterableObject>(5);

	list.set (0, new IterableObject ("patata"));
	list.set (1, new IterableObject ("cacatua"));
	list.set (2, new IterableObject ("tutu"));
	list.set (3, new IterableObject ("baba"));

	return list;
}

void main() {
	var foo = get_iter_list ();

	/* sugar iterator */
	foreach (var obj in foo) {
		print ("- %s\n", obj.name);
	}

	/* manual iteration using API */
	var fit = foo.iterator ();
	while (fit.next ()) {
		IterableObject io = fit.get ();
		print ("= %s\n", io.name);
	}

	/* sugar iterator again */
	foreach (var obj in foo) {
		print ("- %s\n", obj.name);
	}

	/* callback iterator */
/*
	foo.iterator ().for_each ( (x) => {
		// vala does not yet supports generic delegates
		IterableObject *io = x;
		print (" *** %s\n", io->name);
	});

	foo.for_each ( (x) => {
		IterableObject *io = x;
		print (" --- %s\n", io->name);
	});

	foo.for_each ( (x) => {
		IterableObject *io = x;
		print (" yyy %s\n", io->name);
	});
*/

	// r_iter_for_each (foo, iterable_object_unref);
//	foo.foreach ((x) => {
//		delete x;
//	});
/*
	foo.foreach ((x) => {
		IterableObject *io = x;
		print ("+++ %s\n", io->name);
	});
*/
}
