OBJ_BFLT=bin_bflt.o
OBJ_BFLT+=../format/bflt/bflt.o

STATIC_OBJ+=${OBJ_BFLT}
TARGET_BFLT=bin_bflt.${EXT_SO}

ALL_TARGETS+=${TARGET_BFLT}

ifeq ($(WITHNONPIC),1)
LINK+=../../io/libr_io.${EXT_AR}
LINK+=../../util/libr_util.${EXT_AR}
LINK+=../../magic/libr_magic.${EXT_AR}
LINK+=../../socket/libr_socket.${EXT_AR}
LINK+=../../../shlr/gdb/lib/libgdbr.${EXT_AR}
LINK+=../../../shlr/windbg/libr_windbg.${EXT_AR}
LINK+=../../../shlr/qnx/lib/libqnxr.${EXT_AR}
LINK+=../../../shlr/bochs/lib/libbochs.${EXT_AR}
LINK+=../../../shlr/java/libr_java.${EXT_AR}
endif

${TARGET_BFLT}: ${OBJ_BFLT}
	${CC} $(call libname,bin_bflt) ${CFLAGS} \
		$(OBJ_BFLT) $(LINK) $(LDFLAGS)
