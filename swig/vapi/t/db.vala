using Radare;

void main()
{
	var db = new rDatabase();
	db.add_id(0, 4);

	db.add("food");
	db.add("caca");
	db.add("food");

	stdout.printf("%p\n", db.get(0, "caca"));
	stdout.printf("%p\n", db.get(0, "miau"));
	stdout.printf("%p\n", db.get(0, "food"));
	db = null;
}
