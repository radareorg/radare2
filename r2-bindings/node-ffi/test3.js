var r2 = require ("./r_core")

var b = new r2.RBin ()
b.load ("/bin/ls", false);

var baddr = b.get_baddr ();
console.log ("base address: ", baddr);

var sections = b.get_sections ();
console.log ("sections", sections);

r2.a.r_bin_get_sections (b.o);

var secs = (new r2.RList(sections));
var iter = r2.RListIter (secs.iterator ());
//var d = iter.get_data();
//var n = iter.get_next ();
var g = secs.get();
console.log (g);
//console.log (n);
process.exit (0);
if (sections) {
	console.log ("___");
}

console.log ("length", secs.length ());
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
