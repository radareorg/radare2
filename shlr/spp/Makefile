PREFIX?=/usr
BINDIR=${DESTDIR}${PREFIX}/bin
INSTALL_BIN=install -m 0755
OBJ=spp.o main.o r_api.o
ODF=$(subst .o,.d,$(OBJ))
BIN=spp

CFLAGS?=-Wall -O2

CFLAGS+=-fvisibility=hidden

all: ${BIN}

config.h:
	cp config.def.h config.h

${BIN}: config.h ${OBJ}
	${CC} ${LDFLAGS} -o ${BIN} ${OBJ}

r2lib: config.h
	${CC} -DUSE_R2=1 -c ${CFLAGS} ${LDFLAGS} -o spp.o spp.c

symlinks:
	ln -s ${BIN} acr
	ln -s ${BIN} cpp
	ln -s ${BIN} pod
	ln -s ${BIN} sh

test:
	@for a in t/*spp* ; do \
	  printf "Testing $$a... " ; \
	  ./spp -tspp -o out.txt $$a ; \
	  if [ -z "`cat out.txt | grep BUG`" ]; then echo ok ; else echo oops ; fi ; \
	  cat out.txt | grep BUG ; \
	  rm -f out.txt ; \
	  true ; \
	done

install:
	${INSTALL_BIN} ${BIN} ${BINDIR}

uninstall:
	rm -f ${BINDIR}/${BIN}

clean:
	-rm -f ${BIN} ${OBJ} ${ODF}

-include ${ODF}
