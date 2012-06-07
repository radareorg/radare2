var r2 = require ("./r_core")

var b = new r2.RBin ()
b.load ("/bin/ls", false);

var baddr = b.get_baddr ();
console.log ("base address: ", baddr);

var sections = new r2.RList (b.get_sections ());
console.log (sections);

var iter = new r2.RListIter (sections.iterator ());
console.log (sections);

var count = 4;
while (iter != null) {
	console.log (iter);
	var dat = iter.get_data();
	console.log (dat);
	iter = new r2.RListIter (iter.get_next());
	if (count--<1) {
		console.log ("...");
		break;
	}
}
