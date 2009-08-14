CFLAGS=-I../../include -Wall -fPIC -shared -Wl,-R..
# XXX
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__
CFLAGS+=-DCORELIB

foo: all

ALL_TARGETS=
ARCHS=dummy.mk x86_pseudo.mk mreplace.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

.PHONY: all clean foo


#CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..
#CFLAGS_IMP=-I../../include -I../arch/ -I../arch/include -w -fPIC -shared -Wl,-R..
#
#all: parse_dummy.so parse_x86_pseudo.so parse_mreplace.so
#	@true
#
#parse_dummy.so: parse_dummy.o
#	${CC} ${CFLAGS} -o parse_dummy.so parse_dummy.o
#	@#strip -s parse_dummy.so
#
#parse_x86_pseudo.so: parse_x86_pseudo.o
#	${CC} ${CFLAGS} -o parse_x86_pseudo.so parse_x86_pseudo.o
#	@#strip -s parse_x86_pseudo.so
#
#parse_mreplace.so: parse_mreplace.o
#	${CC} ${CFLAGS_IMP} -o parse_mreplace.so \
#		mreplace/mreplace.c mreplace/mmemory.c parse_mreplace.o
#	@#strip -s parse_mreplace.so
#
#clean:
#	-rm -f *.so *.o
