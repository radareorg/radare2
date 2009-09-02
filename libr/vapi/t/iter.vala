using Radare;

//public class IterableObject<G> : Radare.Iter<G> : base(number) {
//[Compact]
public class IterableObject {
	public string name; // { get;set; }

	public IterableObject(string name) {
		this.name = name;
	}
}

IterableObject a;
IterableObject b;
IterableObject c;

Radare.Iter<IterableObject> get_iter_list ()
{
	Radare.Iter<IterableObject> list = new Radare.Iter<IterableObject>(3);
	b = new IterableObject("barata");
	c = new IterableObject("allalt");
	list.set(0, new IterableObject("patata"));
	list.set(1, b);
	list.set(2, c);
	return list;
}

void main()
{
	Radare.Iter<IterableObject> foo = get_iter_list ();
	//Radare.Iter<IterableObject> ptr = foo;
	//for(Radare.Iter<IterableObject> ptr = foo; !ptr.last(); ptr = ptr.next()) {
	while(!foo.last()) {
		//unowned IterableObject io = foo.get ();
		unowned IterableObject io = foo.get ();
		stdout.printf("name: %s\n", io.name);
		foo = foo.next();
	}
}
