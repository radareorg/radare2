all: disasm_x86 disasm_arm disasm_mips disasm_sparc disasm_ppc disasm_bf asm_x86 rasm2 realloc_x86

disasm_x86:
	${CC} -g -I ../../include disasm_x86.c ../libr_asm.a ../../util/*.a -o disasm_x86

disasm_arm:
	${CC} -g -I ../../include disasm_arm.c ../libr_asm.a ../../util/*.a -o disasm_arm

disasm_mips:
	${CC} -g -I ../../include disasm_mips.c ../libr_asm.a ../../util/*.a -o disasm_mips

disasm_sparc:
	${CC} -g -I ../../include disasm_sparc.c ../libr_asm.a ../../util/*.a -o disasm_sparc

disasm_ppc:
	${CC} -g -I ../../include disasm_ppc.c ../libr_asm.a ../../util/*.a -o disasm_ppc

disasm_bf:
	${CC} -g -I ../../include disasm_bf.c ../libr_asm.a ../../util/*.a -o disasm_bf

asm_x86:
	${CC} -g -I ../../include asm_x86.c ../libr_asm.a ../../util/*.a -o asm_x86

rasm2:
	${CC} -g -I ../../include rasm2.c ../libr_asm.a ../../util/*.a -o rasm2

realloc_x86:
	${CC} -g -I ../../include realloc_x86.c ../libr_asm.a ../../bin/*.a ../../util/*.a -o realloc_x86

clean:
	rm -f disasm_x86 disasm_arm disasm_mips disasm_sparc disasm_ppc disasm_bf asm_x86 rasm2 realloc_x86
