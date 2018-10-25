using Radare;
using Json;

public static void entry(RCore core) {
	stdout.printf ("Hello World\n");
	Json.Parser parser = new Json.Parser ();
	try {
		var data = "{\"foo\":123}";
		parser.load_from_data (data);

		// Get the root node:
		Json.Node node = parser.get_root ();

		var type = node.get_node_type ();
		if (type == NodeType.OBJECT) {
			print ("%s\n", Json.to_string(node, true));

			var a = new ObjectIter();
			a.init(node.get_object());

			string name;
			Json.Node val;
			while (a.next(out name, out val)) {
				print ("Name %s\n", name);
				print ("--> %s\n", Json.to_string(val, true));
			}
		}
		print ("Type %s\n", type.to_string());
	} catch (Error e) {
		stderr.printf ("Unable to parse the string: %s\n", e.message);
	}
}
