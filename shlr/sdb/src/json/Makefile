include ../../config.mk

HASOVR=$(shell clang -Wno-initializer-overrides -E -</dev/null 2>&1| grep unknown)
ifeq ($(HASOVR),)
CFLAGS+=-Wno-initializer-overrides
endif
CFLAGS+=-Wall -g -ggdb
BIN=a.out
OBJ=rangstr.o path.o js0n.o api.o main.o
OBJ+=../libsdb.a

all: ${BIN}

${BIN}: ${OBJ}
	${CC} main.c -DMAIN=1 -o ${BIN} ../libsdb.a

clean:
	rm -f ${OBJ} ${BIN}

../libsdb.a:
	cd .. ; ${MAKE} libsdb.a

mrproper: clean
	rm -rf js0n

test:
	./${BIN} glossary.GlossDiv.GlossList.GlossEntry.GlossDef.GlossSeeAlso[0] < test.json | tail -n 1

update:
	rm -rf js0n js0n.c
	${MAKE} js0n.c

js0n.c:
	git clone git://github.com/quartzjer/js0n.git
	cp js0n/js0n.c js0n.c
	rm -rf js0n
