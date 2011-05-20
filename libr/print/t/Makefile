include ../../config.mk

all: hex fmt

BIN=hex
OBJ=hex.o
BINDEPS=r_cons r_line r_print r_util r_anal r_asm r_reg r_syscall r_diff

fmt${EXT_EXE}: fmt.o
	${CC} -I../../include fmt.o -L../../util -lr_util ${LDFLAGS} -o fmt${EXT_EXE}

myclean:
	rm -f fmt fmt.o

include ../../rules.mk
