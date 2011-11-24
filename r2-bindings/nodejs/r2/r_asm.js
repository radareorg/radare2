var FFI = require ("node-ffi");

var RAsmCode = FFI.Struct([
	['int32', 'len']
,	['pointer', 'buf']
,	['string', 'buf_hex']
,	['string', 'buf_asm']
]);

var r = new FFI.Library ("libr_asm", {
	"r_asm_new": [ "pointer", []]
,	"r_asm_set_pc": ["int32", ["pointer","uint64"]]
,	"r_asm_set_syntax": ["int32", ["pointer","int32"]]
,	"r_asm_setup": ["int32", ["pointer","string","int32","int32"]]
,	"r_asm_massemble": ["pointer", ["pointer","string"]]
,	"r_asm_mdisassemble_hexstr": ["pointer", ["pointer","string"]]
});

var ra = new FFI.Library ("libr_asm", {
	"r_asm_new": [ "pointer", []]
,	"r_asm_set_pc": ["int32", ["pointer","uint64"]]
,	"r_asm_set_syntax": ["int32", ["pointer","int32"]]
,	"r_asm_setup": ["int32", ["pointer","string","int32","int32"]]
,	"r_asm_massemble": ["pointer", ["pointer","string"], {"async": true}]
,	"r_asm_mdisassemble_hexstr": ["pointer", ["pointer","string"], {"async": true}]
});

var async = true;

function RAsm() {
	this.setup = function(use, bits, big_endian) {
		return r.r_asm_setup (this.o, use, bits, big_endian);
	}
	if (async) {
		this.o = ra.r_asm_new ();
		this.asm = function(x, y) {
			ra.r_asm_massemble (this.o, x)
				.on ("success", function (ret) {
					y (new RAsmCode (ret));
				});
		}
		this.dasm = function(x) {
			return new RAsmCode (r.r_asm_mdisassemble_hexstr(this.o, x));
		}
	} else {
		this.o = r.r_asm_new ();
		this.asm = function(x,y) {
			return new RAsmCode (r.r_asm_massemble(this.o, x,y));
		}
		this.dasm = function(x,y) {
			return new RAsmCode (r.r_asm_mdisassemble_hexstr(this.o, x,y));
		}
	}
	this.set_pc = function(x) {
		return r.r_asm_set_pc(this.o, x);
	}
	this.set_syntax = function(x) {
		return r.r_asm_set_syntax(this.o, x);
	}
	this.Syntax = {
NONE : 0,
       INTEL: 1,
       ATT: 2
	}
}

exports.RAsm = RAsm;
