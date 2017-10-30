OBJ_R2K = io_r2k.o
ifeq ($(OSTYPE),$(filter $(OSTYPE),gnulinux android))
OBJ_R2K += io_r2k_linux.o
endif
ifeq (${OSTYPE},$(filter $(OSTYPE),windows mingw32 mingw64 cygwin))
OBJ_R2K += io_r2k_windows.o
endif

STATIC_OBJ+=${OBJ_R2K}
TARGET_R2K=io_r2k.${EXT_SO}
ALL_TARGETS+=${TARGET_R2K}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_R2K}: ${OBJ_R2K}
	${CC} $(call libname,io_r2k) ${CFLAGS} -o ${TARGET_R2K} ${OBJ_R2K} ${LINKFLAGS}
