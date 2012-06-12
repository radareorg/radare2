var r2 = require ("./r_core")

var c = new r2.RCore ()
console.log ("pre");
var cons = new r2.RCons (c.get_cons())
console.log ("pos");
var config = r2.RConfig (c.get_config()) // segfault

console.log ("rep");
var ret = c.file_open ("test2.js", false, 0);
console.log ("win");
if (ret.pointer.address != 0) {
console.log ("won");
	//c.bin_load ("test.js");
	//	c.seek (0, true); c.block_read (0);
	//c.cmd0 ("S 0x00000000 0x00000000 0x00013b30 0x00013b30 ehdr rwx");
	c.cmd0 ("o");
	c.cmd0 ("e io.va");
	cons.flush ();
console.log ("cans");
console.log ("sections {");
	c.cmd0 ("om");
	c.cmd0 ("S");
	cons.flush ();
console.log ("}");
c.block_read (0);
	c.cmd0 ("pD 8");
	c.cmd0 ("? 33+4");
	c.cmd0 ("x@0");
	cons.flush ();
} else {
	console.error ("oops: cannot open file");
}
