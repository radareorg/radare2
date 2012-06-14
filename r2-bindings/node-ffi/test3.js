var r2 = require ("./r_core")

var b = new r2.RBin ()
b.load ("/bin/ls", false);

var baddr = b.get_baddr ();
console.log ("base address: ", baddr);

var sections = new r2.RList (b.get_sections ());
console.log (sections);

var iter = new r2.RListIter (sections.iterator ());
console.log (sections);

sections.foreach = function (x) {
	var it = sections.iterator ();
	var iter = new r2.RListIter (it);
	while (iter != null) {
		var dat = iter.get_data ();
		var s = r2.RBinSection (dat);
		console.log (dat);
		//console.log ("-->", dat, s.name);
		console.log ("-->", s);
console.log ("-_>");
		iter = r2.RListIter (iter.get_next ()); //
console.log ("next ", iter);
		//iter = new r2.RListIter (iter.n); //get_next());
	}
}

var count = 4;
sections.foreach (function (x) {
	console.log ("section", x);
});

var iter = r2.RListIter (sections.iterator ());
while (iter != null) {
console.log ("------>");
	var dat = iter.get_data();
	console.log ("data", dat);
	iter = r2.RListIter (iter.get_next());
	if (count--<1) {
		console.log ("...");
		break;
	}
}
