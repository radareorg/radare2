include ../../config.mk

OBJ=rasm2.o
BIN=rasm2${EXT_EXE}
BINDEPS=r_lib r_asm r_print r_cons r_util
LIBS+=-ldl

LDPATH=-L.. -L../../util -L../../lib
LDPATH+=-lr_util -lr_lib
CFLAGS+=-DVERSION=\"${VERSION}\"

all: ${BIN} fastcall${EXT_EXE}

fastcall${EXT_EXE}: fastcall.o
	${CC} fastcall.o ${LDPATH} ${LDFLAGS} -o fastcall${EXT_EXE} 
	@#-Wl,-R.. -L.. -lr_asm -o fastcall

test:
	./rasm2 -f test.asm

myclean:
	rm -f fastcall fastcall.o

include ../../rules.mk
