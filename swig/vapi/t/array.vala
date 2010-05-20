/* radare - LGPL - Copyright 2009-2010 pancake<@nopcode.org> */

// XXX. not implemented

using Radare;

public class TestObject {
	public string name { get; set; }

	public TestObject(string name) {
		this.name = name;
	}
}

RArray<TestObject> get_iter_list () {
	var list = new RArray<TestObject>(5);

	list.set (0, new TestObject ("patata"));
	list.set (1, new TestObject ("cacatua"));
	list.set (2, new TestObject ("tutu"));
	list.set (3, new TestObject ("baba"));

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
		TestObject io = fit.get ();
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
		TestObject *io = x;
		print (" *** %s\n", io->name);
	});

	foo.for_each ( (x) => {
		TestObject *io = x;
		print (" --- %s\n", io->name);
	});

	foo.for_each ( (x) => {
		TestObject *io = x;
		print (" yyy %s\n", io->name);
	});
*/

	// r_iter_for_each (foo, iterable_object_unref);
//	foo.foreach ((x) => {
//		delete x;
//	});
/*
	foo.foreach ((x) => {
		TestObject *io = x;
		print ("+++ %s\n", io->name);
	});
*/
}
