OBJ_DEMANGLE_DLANG=bin_demangle_dlang.o \
	../mangling/dlang.o \
	../mangling/cxx2/dlang.o

CFLAGS+=-DR_BIN_DEMANGLE_DLANG=1
STATIC_OBJ+=${OBJ_DEMANGLE_DLANG}
TARGET_DEMANGLE_DLANG=bin_demangle_dlang.${EXT_SO}
ALL_TARGETS+=${TARGET_DEMANGLE_DLANG}

${TARGET_DEMANGLE_DLANG}: ${OBJ_DEMANGLE_DLANG}
	${CC} $(call libname,bin_demangle_dlang) ${CFLAGS} -o $@ \
		${OBJ_DEMANGLE_DLANG} $(LINK) $(LDFLAGS)
