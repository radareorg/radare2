const r2 = require ('../r_asm');

/* Using the RAsm API */
function Assembler(arch, bits) {
	var $this = new r2.RAsm();
	$this.use(arch);
	$this.set_bits(bits);
    
	this.assemble = function(x) {
		return $this.massemble(x).buf_hex;
	};
	this.disassemble = function(x) {
		return $this.mdisassemble_hexstr(x).buf_asm;
	};
}

var asm = new Assembler('x86', 32);
console.log(asm.assemble('int 0x80;mov eax,33;ret'));
console.log(asm.disassemble('909090'));
