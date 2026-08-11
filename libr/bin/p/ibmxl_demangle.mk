OBJ_DEMANGLE_IBMXL=bin_demangle_ibmxl.o \
	../mangling/ibmxl.o \
	../mangling/cxx2/xlc.o

CFLAGS+=-DR_BIN_DEMANGLE_IBMXL=1
STATIC_OBJ+=${OBJ_DEMANGLE_IBMXL}
TARGET_DEMANGLE_IBMXL=bin_demangle_ibmxl.${EXT_SO}
ALL_TARGETS+=${TARGET_DEMANGLE_IBMXL}

${TARGET_DEMANGLE_IBMXL}: ${OBJ_DEMANGLE_IBMXL}
	${CC} $(call libname,bin_demangle_ibmxl) ${CFLAGS} -o $@ \
		${OBJ_DEMANGLE_IBMXL} $(LINK) $(LDFLAGS)
