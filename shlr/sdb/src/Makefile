include ../config.mk

CFLAGS+= -g -ggdb
#CFLAGS+=-DOLDFMT=1
OBJ=cdb.o buffer.o cdb_make.o ls.o ht.o sdb.o sdbn.o sdba.o query.o
OBJ+=json.o json/js0n.o json/json.o json/rangstr.o ns.o lock.o util.o

SOBJ=$(subst .o,._o,${OBJ})

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
ifneq ($(SILENT),)
	@echo AR libsdb.a
endif
	rm -f libsdb.a
	${AR} -r libsdb.a ${OBJ}
	${RANLIB} libsdb.a

libsdb.${SOEXT}: ${SOBJ}
ifneq ($(SILENT),)
	@echo LIB libsdb.${SOEXT}
endif
	${CC} ${LDFLAGS} $(LDFLAGS_SHARED) -o $@ ${SOBJ}

${BIN}: libsdb.a main.o
ifneq ($(SILENT),)
	@echo BIN ${BIN}
endif
	${CC} ${LDFLAGS} -o ${BIN} main.o ${OBJ}

clean:
	rm -rf ${OBJ} ${SOBJ} main.o libsdb.a a.out ${BIN} sdb.dSYM
	rm -rf *.d *._d json/*.d json/*._d *.sdb *.db *.${SOEXT}

# rules #
.c:
ifneq ($(SILENT),)
	@echo LD $<
endif
	$(CC) $(LDFLAGS) -c $(CFLAGS) -o $@ $<

S=$

%.o: %.c
ifneq ($(SILENT),)
	@echo CC $<
endif
	${CC} -c ${CPPFLAGS} ${CFLAGS} ${CFLAGS_SHARED} -o $@ $<

%._o: %.c
ifneq ($(SILENT),)
	@echo CC PIC $<
endif
	@mv `echo $<|sed -e 's,\.c$S,\.d,g'` $<.tmp 2>/dev/null || true
	${CC} -c ${CPPFLAGS} ${CFLAGS} ${CFLAGS_SHARED} -o $@ $<
	@mv `echo $<|sed -e 's,\.c$S,\.d,g'` `echo $<|sed -e 's,\.c$S,\._d,g'` 2>/dev/null || true
	@mv $<.tmp `echo $<|sed -e 's,\.c$S,\.d,g'` 2>/dev/null ||true

-include ${OBJ:.o=.d}
-include ${OBJ:.o=._d}
