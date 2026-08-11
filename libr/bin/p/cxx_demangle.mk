OBJ_DEMANGLE_CXX=bin_demangle_cxx.o \
	../mangling/cxx.o \
	../mangling/cxx2/itanium.o \
	../mangling/cxx2/xlc.o \
	../mangling/cxx2/gnu-v2.o \
	../mangling/cxx2/armabi.o

ifeq (1,$(WITH_GPL))
OBJ_DEMANGLE_CXX+=../mangling/cxx/cp-demangle.o
endif

CFLAGS+=-DR_BIN_DEMANGLE_CXX=1
STATIC_OBJ+=${OBJ_DEMANGLE_CXX}
TARGET_DEMANGLE_CXX=bin_demangle_cxx.${EXT_SO}
ALL_TARGETS+=${TARGET_DEMANGLE_CXX}

${TARGET_DEMANGLE_CXX}: ${OBJ_DEMANGLE_CXX}
	${CC} $(call libname,bin_demangle_cxx) ${CFLAGS} -o $@ \
		${OBJ_DEMANGLE_CXX} $(LINK) $(LDFLAGS)
