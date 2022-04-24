N=shm
OBJ_SHM=io_shm.o
CSRC_SHM=$(subst .o,.c,$(OBJ_SHM))

STATIC_OBJ+=${OBJ_SHM}
TARGET_SHM=io_shm.${EXT_SO}
#ALL_TARGETS+=${TARGET_SHM}

ifeq (${OSTYPE},gnulinux)
LDFLAGS+=-lrt
endif

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

$(N) p/${TARGET_SHM}: p/${OBJ_SHM}
	cd p && $(CC) $(CFLAGS) -shared -L.. $(CSRC_SHM) -fPIC -o $(TARGET_SHM) -I../../include -I../../../shlr/sdb/src $(LINKFLAGS)
