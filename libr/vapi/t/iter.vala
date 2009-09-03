using Radare;

public class IterableObject {
	public string name; // { get;set; }

	public IterableObject(string name) {
		this.name = name;
	}
}

Radare.GenericIter<IterableObject>* get_iter_list ()
{
	GenericIter<IterableObject> list = new GenericIter<IterableObject>(4);

	list.set(0, new IterableObject("patata"));
	list.set(1, new IterableObject("cacatua"));
	list.set(2, new IterableObject("tutu"));
	list.set(3, new IterableObject("baba"));

	return list;
}

void main()
{
	var foo = get_iter_list ();
	var bar = foo;
	while(!foo->last()) {
		IterableObject io = foo->get ();
		stdout.printf("name: %s\n", io.name);
		foo = foo->next();
	}
	//for(foo=bar;!foo->last();foo=foo->next()) {
	for(foo=bar;!foo->last();foo=foo->next()) {
		IterableObject io = foo->get ();
		stdout.printf("name: %s\n", io.name);
	}
}
