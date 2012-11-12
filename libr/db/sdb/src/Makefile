include ../config.mk
CFLAGS+= -g -ggdb
LDFLAGS+= -g -ggdb
#CFLAGS+=-DOLDFMT=1
OBJ=alloc.o cdb.o buffer.o cdb_make.o ls.o ht.o sdb.o sdbn.o lock.o
OBJ+=json.o json/js0n.o json/json.o json/rangstr.o ns.o

BIN=sdb${EXEXT}

.PHONY: all static shared clean

all: ${BIN}
	${MAKE} static
	${MAKE} shared

sdb-version.h:
	cd .. ; ${MAKE} src/sdb-version.h

shared: sdb-version.h
	${MAKE} libsdb.${SOEXT}

static: sdb-version.h
	${MAKE} libsdb.a

libsdb.a: ${OBJ}
	@#ar qf libasb.a ${OBJ}
	rm -f libsdb.a
	${AR} r libsdb.a ${OBJ}
	${RANLIB} libsdb.a

libsdb.${SOEXT}: ${OBJ}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $(subst .o,.c,${OBJ}) -fPIC -shared

t:
	rm -f foo
	./sdb foo a=3 b=200
	hexdump -C foo
	./sdb foo
	./sdb foo a

tdd test:
	sh tdd.sh

xxx:
	rm -f foo
	./sdb foo a=3
	valgrind ./sdb foo a
	valgrind ./sdb foo a=3 b=4
	valgrind ./sdb foo a=9 b=2

main.c:

${BIN}: libsdb.a main.o
	${CC} ${CFLAGS} -o ${BIN} main.o ${OBJ}

clean:
	rm -rf ${OBJ} libsdb.a a.out sdb sdb.dSYM *.sdb *.db *.${SOEXT}
