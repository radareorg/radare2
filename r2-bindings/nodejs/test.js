var r2 = require ("./r_asm");

/* using the api */
var o = r2.RAsm.new ();
o.use ("x86");
o.set_bits (32);
var ac = o.mdisassemble_hexstr ("909090");
console.log (ac.buf_asm);
var ac = o.massemble ("int 0x80;mov eax,33;ret");
console.log (ac.buf_hex);
o.delete ();
