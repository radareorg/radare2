BINR_PROGRAM=1
include ../../libr/config.mk
include ../../shlr/zip/deps.mk
include ../../shlr/sdb.mk

# despite libs are pic, some systems/compilers dont
# like relocatable executables, so here we do the magic
USE_PIE=0
ifeq (,$(findstring emcc,${CC}))
USE_PIE=1
else
ifeq (,$(findstring tcc,${CC}))
USE_PIE=1
else
ifeq (,$(findstring vinix,${CC}))
USE_PIE=1
else
ifeq (,$(findstring wasm,${CC}))
USE_PIE=1
else
USE_PIE=0
endif
endif
endif
endif
endif
endif

ifeq ($(USE_PIE),1)
CFLAGS+=-pie
endif
CFLAGS:=-I$(LTOP)/include $(CFLAGS)

ifeq (${ANDROID},1)
CFLAGS+=-lm
LDFLAGS+=-lm
else
ifneq (${OSTYPE},linux)
LDFLAGS+=-lpthread
ifeq (${OSTYPE},freebsd)
LDFLAGS+=-ldl
endif
LDFLAGS+=-lm
endif
endif
ifeq ($(USE_LTO),1)
LDFLAGS+=-flto
endif

ifeq (${COMPILER},wasi)
LINK+=$(SHLR)/zip/librz.a
LINK+=$(SHLR)/gdb/lib/libgdbr.a
LINK+=$(CS_ROOT)/libcapstone.a
LINK+=$(SHLR)/../subprojects/sdb/src/libsdb.a

# instead of libr.a
LINK+=$(LIBR)/util/libr_util.a
LINK+=$(LIBR)/core/libr_core.a
LINK+=$(LIBR)/magic/libr_magic.a
LINK+=$(LIBR)/socket/libr_socket.a
LINK+=$(LIBR)/debug/libr_debug.a
LINK+=$(LIBR)/anal/libr_anal.a
LINK+=$(LIBR)/reg/libr_reg.a
LINK+=$(LIBR)/bp/libr_bp.a
LINK+=$(LIBR)/io/libr_io.a
LINK+=$(LIBR)/flag/libr_flag.a
LINK+=$(LIBR)/syscall/libr_syscall.a
LINK+=$(LIBR)/egg/libr_egg.a
LINK+=$(LIBR)/fs/libr_fs.a
LINK+=$(LIBR)/bin/libr_bin.a
LINK+=$(LIBR)/asm/libr_asm.a
LINK+=$(LIBR)/search/libr_search.a
LINK+=$(LIBR)/cons/libr_cons.a
LINK+=$(LIBR)/lang/libr_lang.a
LINK+=$(LIBR)/config/libr_config.a
LINK+=$(LIBR)/muta/libr_muta.a
LINK+=$(LIBR)/main/libr_main.a
else ifeq (${COMPILER},wasm)
LINK+=$(SHLR)/libr_shlr.a
LINK+=$(SHLR)/../subprojects/sdb/src/libsdb.a
include $(SHLR)/capstone.mk
EXT_EXE=.wasm
else ifeq (${COMPILER},emscripten)
LINK+=$(SHLR)/libr_shlr.a
LINK+=$(SHLR)/../subprojects/sdb/src/libsdb.a
include $(SHLR)/capstone.mk
CFLAGS+= -s SIDE_MODULE=1
#CFLAGS+=-s ERROR_ON_UNDEFINED_SYMBOLS=0
#EXT_EXE=.js
#EXT_EXE=.html
EXT_EXE=.bc
#EXT_EXE=.wasm
endif

LDFLAGS+=$(LDFLAGS_RPATH)

OBJ+=${BIN}.o
BEXE=${BIN}${EXT_EXE}

LDFLAGS+=${DL_LIBS}
ifneq (${ANDROID},1)
ifneq (${OSTYPE},windows)
ifneq (${OSTYPE},linux)
ifneq ($(CC),cccl)
LDFLAGS+=-lpthread
endif
endif
endif
endif

REAL_LDFLAGS=$(subst -shared,,$(LDFLAGS))

ifeq ($(ISLIB),1)
BEXE=$(BIN).$(EXT_SO)
REAL_LDFLAGS+=-shared
endif
#--------------------#
# Rules for programs #
#--------------------#

LDFLAGS+=-lm
# For some reason w32 builds contain -shared in LDFLAGS. boo!

ifneq ($(BIN)$(BINS),)

ifeq ($(OSTYPE),linux)
LDFLAGS+=-static
endif

all: ${BEXE} ${BINS}

ifeq ($(WITH_LIBR),1)
${BINS}: ${OBJS}
	${CC} ${CFLAGS} $@.c ${OBJS} ../../libr/libr.a -o $@ $(LDFLAGS)

${BEXE}: ${OBJ} ${SHARED_OBJ}
 ifeq ($(COMPILER),wasi)
  ifeq ($(OSTYPE),wasi-api)
	${CC} ${CFLAGS} $+ -L.. -o $@ $(LDFLAGS) -Wl,--no-entry -Wl,--export-all -mexec-model=reactor
  else
	${CC} ${CFLAGS} $+ -L.. -o $@ $(LDFLAGS)
  endif
 else
	${CC} ${CFLAGS} $+ -L.. -o $@ ../../libr/libr.a $(LDFLAGS)
 endif
else

${BINS}: ${OBJS}
ifneq ($(SILENT),)
	@echo CC $@
endif
	${CC} ${CFLAGS} $@.c ${OBJS} ${REAL_LDFLAGS} $(LINK) -o $@

include ../../config-user.mk

${BEXE}: ${OBJ} ${SHARED_OBJ}
# -static fails because -ldl -lpthread static-gcc ...
ifneq ($(SILENT),)
	@echo LD $@
endif
	${CC} ${CFLAGS} $+ -L.. -o $@ $(REAL_LDFLAGS) $(LINK)
endif
endif

# Dummy myclean rule that can be overridden by the t/ Makefile
# TODO: move to config.mk ? it must be a precondition
myclean:

clean:: myclean
	-rm -f ${OBJS} ${OBJ} ${BEXE}

mrproper: clean
	-rm -f *.d

ifeq ($(INSTALL_TARGET),)
install:
	cd ../.. && ${MAKE} install
endif

.PHONY: all clean myclean mrproper install
