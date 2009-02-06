LDFLAGS=-L../../util -lr_util -L../ -lr_asm
LDFLAGS_BIN=${LDFLAGS} -lr_bin -L../../bin
all: disasm_x86 disasm_arm disasm_mips disasm_sparc disasm_ppc disasm_bf asm_x86 rasm2 realloc_x86

disasm_x86:
	${CC} -g -I ../../include disasm_x86.c ${LDFLAGS} -o disasm_x86

disasm_arm:
	${CC} -g -I ../../include disasm_arm.c ${LDFLAGS} -o disasm_arm

disasm_mips:
	${CC} -g -I ../../include disasm_mips.c ${LDFLAGS} -o disasm_mips

disasm_sparc:
	${CC} -g -I ../../include disasm_sparc.c ${LDFLAGS} -o disasm_sparc

disasm_ppc:
	${CC} -g -I ../../include disasm_ppc.c ${LDFLAGS} -o disasm_ppc

disasm_bf:
	${CC} -g -I ../../include disasm_bf.c ${LDFLAGS} -o disasm_bf

asm_x86:
	${CC} -g -I ../../include asm_x86.c ${LDFLAGS} -o asm_x86

rasm2:
	${CC} -g -I ../../include rasm2.c ${LDFLAGS} -o rasm2

realloc_x86:
	${CC} -g -I ../../include realloc_x86.c ${LDFLAGS_BIN} -o realloc_x86

clean:
	rm -f disasm_x86 disasm_arm disasm_mips disasm_sparc disasm_ppc disasm_bf asm_x86 rasm2 realloc_x86
