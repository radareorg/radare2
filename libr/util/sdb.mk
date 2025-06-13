# SUBPROJECTS TODO sdb
SDBPATH=$(SHLR)/../subprojects/sdb/src/
SDBINCDIR=$(SHLR)/../subprojects/sdb/include
SDBLIB=${SDBPATH}/libsdb.a
EXTRA_TARGETS+=${SDBLIB}
EXTRA_PRE+=$(SDBLIB)

# __wasi__
# CFLAGS+=-DUSE_MMAN=0
# CFLAGS+=-DHAVE_MMAN=0

SDB_OBJS=
SDB_OBJS+=cdb.o
SDB_OBJS+=heap.o
SDB_OBJS+=cgen.o
SDB_OBJS+=strbuf.o
SDB_OBJS+=set.o
SDB_OBJS+=cdb_make.o
SDB_OBJS+=ht_uu.o
SDB_OBJS+=ht_up.o
SDB_OBJS+=ht_pp.o
SDB_OBJS+=ht_pu.o
SDB_OBJS+=ht_su.o
SDB_OBJS+=ht.o
SDB_OBJS+=json.o
SDB_OBJS+=text.o
SDB_OBJS+=lock.o
SDB_OBJS+=ls.o
SDB_OBJS+=ns.o
SDB_OBJS+=query.o
SDB_OBJS+=sdb.o
SDB_OBJS+=base64.o
SDB_OBJS+=disk.o
SDB_OBJS+=dict.o
SDB_OBJS+=array.o
SDB_OBJS+=fmt.o
SDB_OBJS+=match.o
SDB_OBJS+=num.o
SDB_OBJS+=util.o
SDB_OBJS+=journal.o
SDB_OBJS+=diff.o

SDBOBJS=$(addprefix ${SDBPATH},${SDB_OBJS})

OBJS+=$(SDBOBJS)

CFLAGS+=-I$(SDBINCDIR)

$(SDBLIB):
	$(MAKE) -C ../../shlr sdbs
