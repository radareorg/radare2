include ../config.mk
#CFLAGS+=-DOLDFMT=1
OBJ=alloc.o cdb.o buffer.o cdb_make.o ls.o ht.o sdb.o sdbn.o lock.o
# This is hacky
SOEXT=dylib
#SOEXT=so
ARCH=$(shell uname -m)
RANLIB?=ranlib
EXEXT=

BIN=sdb${EXEXT}

.PHONY: all libsdb.${SOEXT} clean wcl syms

all: libsdb.a ${BIN}

libsdb.a: ${OBJ}
	@#ar qf libasb.a ${OBJ}
	ar -r libsdb.a ${OBJ}
	${RANLIB} libsdb.a

libsdb.${SOEXT}:
	${CC} -o $@ $(subst .o,.c,${OBJ}) -fPIC -shared -arch ${ARCH}
	sudo cp libsdb.${SOEXT} ${PREFIX}/lib

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
	#${CC} ${CFLAGS} -o ${BIN} main.c libsdb.a

wcl:
	wc -l `echo ${OBJ}|sed -e 's,\.o,.c,g'`

clean:
	rm -rf ${OBJ} libsdb.a a.out sdb sdb.dSYM *.sdb *.db *.${SOEXT}
