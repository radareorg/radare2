var r2 = require ("./r_core")

var c = new r2.RCore ()
var cons = new r2.RCons (c.cons)

var ret = c.file_open ("test2.js", false, 0);
if (ret.pointer.address != 0) {
	//console.log ("ret = ", ret);
	c.bin_load ("test2.js"); // if not called it will not work XXX must fix
	c.seek (0, true);
	c.block_read (0);
	c.cmd0 ("o");
	c.cmd0 ("pD 8");
	c.cmd0 ("? 33+4");
	c.cmd0 ("x@0");
	cons.flush ();
} else {
	console.error ("oops: cannot open file");
}
