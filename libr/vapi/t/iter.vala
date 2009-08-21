using Radare;

public class IterableObject : Radare.Iter {
	public string name { get;set; }

	public IterableObject(string name) {
		this.name = name;
	}
}

Radare.Iter<IterableObject> get_iter_list ()
{
	Radare.Iter<IterableObject> list = new Radare.Iter<IterableObject>(3);
	list.set(0, new IterableObject("patata"));
	list.set(1, new IterableObject("barata"));
	list.set(2, new IterableObject("lalata"));
	return list;
}

void main()
{
	Radare.Iter<IterableObject> foo = get_iter_list ();
	while (!foo.last ()) {
		unowned IterableObject io = foo.get ();
		stdout.printf("name: %s\n", io.name);
	}
}
