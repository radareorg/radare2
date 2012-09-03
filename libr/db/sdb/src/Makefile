include ../config.mk
CFLAGS+= -g -ggdb
LDFLAGS+= -g -ggdb
#CFLAGS+=-DOLDFMT=1
OBJ=alloc.o cdb.o buffer.o cdb_make.o ls.o ht.o sdb.o sdbn.o lock.o
OBJ+=json.o json/js0n.o json/json.o json/rangstr.o ns.o
# This is hacky
OS=$(shell uname)
ARCH=$(shell uname -m)
ifeq (${OS},Darwin)
SOEXT=dylib
LDFLAGS+=-dynamic
 ifeq (${ARCH},i386)
   CC+=-arch i386 -arch x86_64
 endif
else
SOEXT=so
endif
RANLIB?=ranlib
EXEXT=

BIN=sdb${EXEXT}

.PHONY: all static shared clean wcl syms

all: static shared ${BIN}

shared: libsdb.${SOEXT}

static: libsdb.a

libsdb.a: ${OBJ}
	@#ar qf libasb.a ${OBJ}
	rm -f libsdb.a
	${AR} -r libsdb.a ${OBJ}
	${RANLIB} libsdb.a

libsdb.${SOEXT}: ${OBJ}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $(subst .o,.c,${OBJ}) -fPIC -shared

t:
	rm -f foo
	./sdb foo a=3 b=200
	hexdump -C foo
	./sdb foo
	./sdb foo a

test:
	rm -f foo
	./sdb foo a=3
	valgrind ./sdb foo a
	valgrind ./sdb foo a=3 b=4
	valgrind ./sdb foo a=9 b=2

syms:
	otool -Vt sdb|grep callq |awk '{print $$3}'|grep -v 0x|sort|uniq > symbols-used
	otool -Vt sdb| grep ^_ |sed -e s,:,,|sort|uniq > symbols-found
	diff -ru symbols-found symbols-used | grep ^-
	rm -f symbols-found symbols-used

main.c:

${BIN}: libsdb.a main.c
	${CC} ${CFLAGS} -o ${BIN} main.c ${OBJ}
	#libsdb.a

wcl:
	wc -l `echo ${OBJ}|sed -e 's,\.o,.c,g'`

clean:
	rm -rf ${OBJ} libsdb.a a.out sdb sdb.dSYM *.sdb *.db *.${SOEXT}
