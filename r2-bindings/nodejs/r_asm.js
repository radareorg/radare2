var FFI = require("node-ffi");

var a = new FFI.Library ("libr_asm", {
	"r_asm_new": [ "pointer" , []]
,	"r_asm_free": [ "void" , ["pointer"]]
,	"r_asm_use": [ "int" , [ "pointer", "string"]]
,	"r_asm_set_bits": [ "int" , [ "pointer", "int"]]
,	"r_asm_set_pc": [ "int" , [ "pointer", "uint64"]]
,	"r_asm_mdisassemble_hexstr": [ "pointer", ["pointer", "string"] ]
,	"r_asm_massemble": [ "pointer", ["pointer", "string"] ]
,	"r_asm_assemble_file": [ "pointer", ["pointer", "string"] ]
,	"r_asm_filter_input": [ "int", ["pointer", "string"] ]
,	"r_asm_filter_output": [ "int", ["pointer", "string"] ]
});
var RAsmCode = FFI.Struct([
	['int32', 'len']
,	['string', 'buf']
,	['string', 'buf_hex']
,	['string', 'buf_asm']
,	['pointer', 'foo']
,	['int64', 'bar']
,	['int64', 'cow']
]);

var RAsm = FFI.Struct ([
	['int', 'bits']
,	['int', 'big_endian']
,	['int', 'syntax']
// ...
])

/* init */
// TODO: make valabind generate this stub
RAsm.new = function () {
	var p = a.r_asm_new ();
	p.use = function (x) {
		return a.r_asm_use (p, x);
	}
	p.set_pc = function (x) {
		return a.r_asm_set_pc (p, x);
	}
	p.set_bits = function (x) {
		return a.r_asm_set_bits (p, x);
	}
	p.filter_input = function (x) {
		return a.r_asm_filter_input (p, x);
	}
	p.filter_output = function (x) {
		return a.r_asm_filter_output (p, x);
	}
	p.mdisassemble_hexstr = function (x) {
		return new RAsmCode (a.r_asm_mdisassemble_hexstr (p, x));
	}
	p.massemble = function (x) {
		return new RAsmCode (a.r_asm_massemble (p, x));
	}
	p.assemble_file = function (x) {
		return new RAsmCode (a.r_asm_assemble_file (p, x));
	}
	p.delete = function (x) {
		a.r_asm_free (p);
	}
	return p;
}
/* libm
var FFI = require("node-ffi");

var libm = new FFI.Library("libm", { "ceil": [ "double", [ "double" ] ] });
libm.ceil(1.5); // 2
*/
var r2 = {
	RAsm : RAsm
}
module.exports = r2;
