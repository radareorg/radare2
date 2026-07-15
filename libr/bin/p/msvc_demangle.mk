OBJ_DEMANGLE_MSVC=bin_demangle_msvc.o \
	../mangling/msvc.o \
	../mangling/microsoft.o \
	../mangling/demangler.o

CFLAGS+=-DR_BIN_DEMANGLE_MSVC=1
STATIC_OBJ+=${OBJ_DEMANGLE_MSVC}
TARGET_DEMANGLE_MSVC=bin_demangle_msvc.${EXT_SO}
ALL_TARGETS+=${TARGET_DEMANGLE_MSVC}

${TARGET_DEMANGLE_MSVC}: ${OBJ_DEMANGLE_MSVC}
	${CC} $(call libname,bin_demangle_msvc) ${CFLAGS} -o $@ \
		${OBJ_DEMANGLE_MSVC} $(LINK) $(LDFLAGS)
