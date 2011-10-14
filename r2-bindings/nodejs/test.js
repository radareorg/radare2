const r2 = require ("./r_asm");
const print = console.log;

/* using the api */
function Assembler (arch, bits) {
	var o = new r2.RAsm ();
	o.use (arch);
	o.set_bits (bits);

	this.delete = function () {
		o.delete ();
	}
	this.assemble = function (x) {
		var ac = o.massemble (x);
		return ac.buf_hex;
	}
	this.disassemble = function (x) {
		var ac = o.mdisassemble_hexstr (x);
		return ac.buf_asm;
	}
}

var asm = new Assembler ("x86", 32);
print (asm.assemble ("int 0x80;mov eax,33;ret"));
print (asm.disassemble ("909090"));
asm.delete ();

process.exit (0);
