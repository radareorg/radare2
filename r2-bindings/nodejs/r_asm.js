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
var RAsmCode = FFI.Struct ([
	['int32', 'len']
,	['string', 'buf']
,	['string', 'buf_hex']
,	['string', 'buf_asm']
,	['pointer', 'foo']
,	['int64', 'bar']
,	['int64', 'cow']
]);

// XXX wrong name?
var RAsm = FFI.Struct ([
	['int', 'bits']
,	['int', 'big_endian']
,	['int', 'syntax']
// ...
])

/* libm
var FFI = require("node-ffi");

var libm = new FFI.Library("libm", { "ceil": [ "double", [ "double" ] ] });
libm.ceil(1.5); // 2
*/
var r2 = {
	RAsm : function() {
		/* lifecycle */
		var p = a.r_asm_new ();
		this.destroy = function (x) {
			a.r_asm_free (p);
		}

		/* methods */
		this.use = function(x) {
			return a.r_asm_use (p, x);
		}
		this.set_pc = function (x) {
			return a.r_asm_set_pc (p, x);
		}
		this.set_bits = function (x) {
			return a.r_asm_set_bits (p, x);
		}
		this.filter_input = function (x) {
			return a.r_asm_filter_input (p, x);
		}
		this.filter_output = function (x) {
			return a.r_asm_filter_output (p, x);
		}
		this.mdisassemble_hexstr = function (x) {
			return new RAsmCode (a.r_asm_mdisassemble_hexstr (p, x));
		}
		this.massemble = function (x) {
			return new RAsmCode (a.r_asm_massemble (p, x));
		}
		this.assemble_file = function (x) {
			return new RAsmCode (a.r_asm_assemble_file (p, x));
		}
	}
}

module.exports = r2;
