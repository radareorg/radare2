OBJ_DEMANGLE_RUST=bin_demangle_rust.o \
	../mangling/rust.o \
	../mangling/cxx2/rust.o \
	../mangling/cxx.o \
	../mangling/cxx2/itanium.o \
	../mangling/cxx2/xlc.o \
	../mangling/cxx2/gnu-v2.o \
	../mangling/cxx2/armabi.o

ifeq (1,$(WITH_GPL))
OBJ_DEMANGLE_RUST+=../mangling/cxx/cp-demangle.o
endif

CFLAGS+=-DR_BIN_DEMANGLE_RUST=1 -DR_BIN_DEMANGLE_CXX=1
STATIC_OBJ+=${OBJ_DEMANGLE_RUST}
TARGET_DEMANGLE_RUST=bin_demangle_rust.${EXT_SO}
ALL_TARGETS+=${TARGET_DEMANGLE_RUST}

${TARGET_DEMANGLE_RUST}: ${OBJ_DEMANGLE_RUST}
	${CC} $(call libname,bin_demangle_rust) ${CFLAGS} -o $@ \
		${OBJ_DEMANGLE_RUST} $(LINK) $(LDFLAGS)
