using Radare;

//public class IterableObject<G> : Radare.Iter<G> : base(number) {
[Compact]
public class IterableObject {
	public string name; // { get;set; }

	public IterableObject(string name) {
		this.name = name;
	}
}

Radare.Iter<IterableObject> get_iter_list ()
{
	Radare.Iter<unowned IterableObject> list = new Radare.Iter<unowned IterableObject>(3);
	list.set(0, new IterableObject("patata"));
	list.set(1, new IterableObject("barata"));
	list.set(2, new IterableObject("lalata"));
	return list;
}

void main()
{
	Radare.Iter<unowned IterableObject> foo = get_iter_list ();
	//Radare.Iter<IterableObject> ptr = foo;
	//for(Radare.Iter<IterableObject> ptr = foo; !ptr.last(); ptr = ptr.next()) {
	while(!foo.last()) {
		//unowned IterableObject io = foo.get ();
		unowned IterableObject io = foo.get ();
		stdout.printf("name: %s\n", io.name);
		foo = foo.next();
	}
}
