OBJ_BFLT=bin_bflt.o
OBJ_BFLT+=../format/bflt/bflt.o

STATIC_OBJ+=${OBJ_BFLT}
TARGET_BFLT=bin_bflt.${EXT_SO}

ALL_TARGETS+=${TARGET_BFLT}

ifeq ($(WITHNONPIC),1)
LINK+=../../io/libr_io.a
LINK+=../../util/libr_util.a
LINK+=../../magic/libr_magic.a
LINK+=../../socket/libr_socket.a
LINK+=../../../shlr/gdb/lib/libgdbr.a
LINK+=../../../shlr/bochs/lib/libbochs.a
LINK+=../../../shlr/java/libr_java.a
endif

${TARGET_BFLT}: ${OBJ_BFLT}
	${CC} $(call libname,bin_bflt) ${CFLAGS} \
		$(OBJ_BFLT) $(LINK) $(LDFLAGS)
