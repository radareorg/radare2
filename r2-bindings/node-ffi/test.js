const r2 = require ('./r_asm');

/* using the api */
function Assembler(arch, bits) {
    var o = new r2.RAsm();
    o.use(arch);
    o.set_bits(bits);
    
    this.delete = function() {
        o.delete();
    };
    this.assemble = function(x) {
        var r = o.massemble(x), buf = r.buf_hex;
        r.delete();
        return buf;
    };
    this.disassemble = function(x) {
        var r = o.mdisassemble_hexstr(x), buf = r.buf_asm;
        r.delete();
        return buf;
    };
}

var asm = new Assembler('x86', 32);
console.log(asm.assemble('int 0x80;mov eax,33;ret'));
console.log(asm.disassemble('909090'));
asm.delete();
