RArch transition plan
=====================

The refactoring plan to merge asm and anal plugins is the following:

* Asm and Anal plugins will be reimplemented as Arch plugins
* Asm plugins will be the parse ones
* Anal plugins will be used to extend the analysis
* RParse API must be loaded into RAsm

* Arch APIs will cover:
  - retrieve register profile
  - provide arch details information
  - encode and decode instructions (RAnalOp)
  - instruction descriptions (asm/d)
* Asm APIs will cover:
  - assemble one instruction using the arch plugins
  - asm plugins will be there until all of them get moved 
* Anal APIs will cover:
  - analyzing an opcode

RAnalOp + RAsmOp = RArchInstruction

Questions
---------

* What about using different plugins to encode or decode?
  - let's say we want x86.cs to decode and x86.as to encode
  - can we "nest" one plugin after another?

```c
// C
RArch *a = r_arch_new ();
r_arch_setup (a, "x86", 64, R_SYS_ENDIAN_LITTLE);
RArchInstruction ins;
r_arch_instruction_init (&ins, addr, "\x90", 1);
if (r_arch_decode (a, &ins, R_ARCH_OPTION_DISASM)) {
	eprintf ("Disassembled: %s\n", r_arch_instruction_disasm (&ins);
}
```

```go
// V
import r_arch

a := r_arch.new()
if !a.setup('x86', 64, a.ENDIAN_LITTLE) {
	eprintln('Error setting up the arch plugin')
}
ins := r_arch.instruction_new (0, '\x90', 1)
if a.decode(ins, a.OPTION_DISASM) {
	println('disassembled: $ins.disasm()')
}
a.free()
```
