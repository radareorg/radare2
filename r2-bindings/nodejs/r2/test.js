#!/usr/bin/env node
/* Hello World using nodejs-ffi bindings for r2's r_asm api */

var r = require ("./r_asm");

var a = new r.RAsm ();
a.setup ("x86", 32, false);

a.asm ("nop;mov eax,33", function(x) {
	var c = new RAsmCode (x);
	console.log ("done" + c.buf_hex);
});
console.log ("continue");

setTimeout(function() {
	console.log("pepep");
}, 30);

var FFI = require ("node-ffi");
var libc = new FFI.Library("libc", {
	"sleep":  ["int32", ["int32"]]
});

libc.sleep (3);

process.exit (0);

console.log (a.asm ("nop;mov eax,33").buf_hex);
a.setup ("x86", 64, false);
console.log (a.asm ("nop;mov rax,33").buf_hex);
a.set_pc (33);

a.set_syntax (a.Syntax.ATT);
console.log (a.dasm ("9048c7c02100000090cd329090").buf_asm);

var r = 33;
