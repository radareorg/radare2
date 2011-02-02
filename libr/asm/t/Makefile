include ../../config.mk

BINDEPS=r_lib r_asm r_util
LIBS+=-ldl

LDPATH=-L.. -L../../util -L../../lib
LDPATH+=-lr_util -lr_lib
CFLAGS+=-DVERSION=\"${VERSION}\"

all:

# XXX: remove fastcall program here , it has been moved into RSyscall
# fastcall${EXT_EXE}

fastcall${EXT_EXE}: fastcall.o
	${CC} fastcall.o ${LDPATH} ${LDFLAGS} -o fastcall${EXT_EXE} 

myclean:
	rm -f fastcall fastcall.o

include ../../rules.mk
