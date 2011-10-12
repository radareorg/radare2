const pathtogir = "/Users/pancake/prg/node-gir/";

var gir = require (pathtogir+"/gir");
gir.init();

var r2 = gir.load("RAsm", "1.0");
var r2core = gir.load("RCore", "1.0");
console.log (r2);
console.log (r2core);

var IntelSyntax = r2.RAsmSyntax.intel;

console.log ("INTEL_SYNTAX = "+IntelSyntax);

/* This is not working +/
const r = imports.gi.r_asm.Radare;
var b = new r.RAsm ();
for (var a in r) {
	print (a);
}
*/
