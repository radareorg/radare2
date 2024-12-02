# deprecate.. move into subprojects/sdb-deps.mk
SDB_ROOT=$(SHLR)/../subprojects/sdb
SDB_CFLAGS+=-I$(SDB_ROOT)/include
SDB_LDFLAGS+=$(SDB_ROOT)/lib/lib_sdb.a
CFLAGS+=$(SDB_CFLAGS)
