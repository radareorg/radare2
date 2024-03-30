include ../config.mk

# CFLAGS:=-g $(CFLAGS)
OBJ=cdb.o cdb_make.o ls.o ht.o ht_uu.o sdb.o num.o base64.o match.o
OBJ+=json.o ns.o lock.o util.o disk.o query.o array.o fmt.o journal.o text.o
OBJ+=dict.o ht_pp.o ht_up.o ht_pu.o ht_su.o set.o diff.o heap.o main.o
SDB_CFLAGS+=-I../include
SDB_CXXFLAGS+=-I../include
SOBJ=$(subst .o,.o.o,${OBJ})
WITHPIC?=1
BIN=sdb${EXT_EXE}

.PHONY: all static shared clean mrproper install

all: $(BIN)
	$(MAKE) static
ifeq ($(WITHPIC),1)
	$(MAKE) shared
endif

json.o: json/api.c json/js0n.c json/path.c json/rangstr.c json/indent.c

install:
	$(MAKE) -C .. install

../include/sdb/version.h:
	$(MAKE) -C .. include/sdb/version.h

shared: ../include/sdb/version.h
	$(MAKE) libsdb${SOVER}

static: ../include/sdb/version.h
	$(MAKE) libsdb$(EXT_AR)

sdb_objs: ../include/sdb/version.h
	$(MAKE) ${OBJ}

sdb_objs2: ../include/sdb/version.h
	$(MAKE) ${SOBJ}

libsdb.lib libsdb$(EXT_AR): sdb_objs
ifneq ($(SILENT),)
	@echo AR libsdb$(EXT_AR)
endif
	rm -f libsdb$(EXT_AR)
	${AR} q libsdb$(EXT_AR) ${OBJ}
	${RANLIB} libsdb$(EXT_AR)

ifeq ($(CC),tcc)
libsdb${SOVER}:
	@echo TCC doesnt support shared libs on macos
else
libsdb${SOVER}: sdb_objs2
endif
ifneq ($(EXT_SO),${SOVER})
	ln -fs libsdb${SOVER} libsdb${EXT_SO}
endif
ifneq ($(SILENT),)
	@echo LIB libsdb${SOVER}
endif
	$(CC) ${LDFLAGS} $(LDFLAGS_SHARED) -o $@ ${SOBJ}

bin_deps: ../include/sdb/version.h
	$(MAKE) libsdb.a entry.o

bin $(BIN): bin_deps
ifneq ($(SILENT),)
	@echo BIN ${BIN}
endif
	$(CC) ${LDFLAGS} -o ${BIN} entry.o ${OBJ}

mrproper clean:
	rm -rf ${OBJ} ${SOBJ} entry.o libsdb.a a.out ${BIN} sdb.dSYM
	rm -rf *.d *._d json/*.d json/*._d *.sdb *.db *.dylib *.dll *.so *.so.*

# rules #
.c:
ifneq ($(SILENT),)
	@echo LD $<
endif
	$(CC) $(LDFLAGS) -c $(CFLAGS) $(SDB_CFLAGS) -o $@ $<

S=$

%.o: %.c
ifneq ($(SILENT),)
	@echo CC $<
endif
	$(CC) -c ${CPPFLAGS} ${CFLAGS} $(SDB_CFLAGS) ${CFLAGS_SHARED} -o $@ $<

%.o.o: %.c
ifneq ($(SILENT),)
	@echo CC PIC $<
endif
	@mv `echo $<|sed -e 's,\.c$S,\.d,g'` $<.tmp 2>/dev/null || true
	$(CC) -c ${CPPFLAGS} ${CFLAGS} $(SDB_CFLAGS) ${CFLAGS_SHARED} -o $@ $<
	@mv `echo $<|sed -e 's,\.c$S,\.d,g'` `echo $<|sed -e 's,\.c$S,\._d,g'` 2>/dev/null || true
	@mv $<.tmp `echo $<|sed -e 's,\.c$S,\.d,g'` 2>/dev/null ||true

-include ${OBJ:.o=.d}
-include ${OBJ:.o=._d}
