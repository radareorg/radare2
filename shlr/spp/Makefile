include config.mk

PWD=$(shell pwd)
PREFIX?=/usr
BINDIR=${DESTDIR}${PREFIX}/bin
OBJ=spp.o bin/main.o
# r_api.o
ODF=$(subst .o,.d,$(OBJ))
BIN=spp

ifeq ($(SPP_USE_R2),1)
CFLAGS+=$(shell pkg-config --cflags r_util)
LDFLAGS+=$(shell pkg-config --libs r_util)
endif

CFLAGS?=-Wall -O2

CFLAGS+=-fvisibility=hidden
CFLAGS+=-DUSE_R2=$(SPP_USE_R2)
CFLAGS+=-DHAVE_FORK=$(SPP_HAVE_FORK)
CFLAGS+=-DVERSION=$(VERSION)

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
	mkdir -p ${BINDIR}
	${INSTALL_PROGRAM} ${BIN} ${BINDIR}

symstall:
	mkdir -p ${BINDIR}
	ln -fs $(PWD)/${BIN} ${BINDIR}/$(BIN)

uninstall:
	rm -f ${BINDIR}/${BIN}

clean:
	-rm -f ${BIN} ${OBJ} ${ODF}

-include ${ODF}
