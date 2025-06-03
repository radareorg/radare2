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
R_IO_SHM_LINKFLAGS+=../../util/libr_util.a
R_IO_SHM_LINKFLAGS+=../../io/libr_io.a
R_IO_SHM_LINKFLAGS+=../../cons/libr_cons.a
R_IO_SHM_LINKFLAGS+=../../cons/libr_socket.a
else
R_IO_SHM_LINKFLAGS+=-L../../cons -lr_cons
R_IO_SHM_LINKFLAGS+=-L../../util -lr_util
R_IO_SHM_LINKFLAGS+=-L../../socket -lr_socket
R_IO_SHM_LINKFLAGS+=-L../../muta -lr_muta
R_IO_SHM_LINKFLAGS+=-L.. -lr_io
endif

$(N) p/${TARGET_SHM}: p/${OBJ_SHM}
	cd p && $(CC) $(CFLAGS) -shared -L.. $(CSRC_SHM) -fPIC -o $(TARGET_SHM) -I../../include -I../../../subprojects/sdb/src $(R_IO_SHM_LINKFLAGS)
