BINR_PROGRAM=1
include ../../libr/config.mk
include ../../shlr/zip/deps.mk

ifneq ($(OSTYPE),windows)
# tcc doesn't recognize the -pie option
ifeq (,$(findstring tcc,${CC}))
CFLAGS+=-pie
endif
endif
CFLAGS+=-I$(LTOP)/include

ifeq (${COMPILER},emscripten)
EXT_EXE=.js
endif

ifeq ($(USE_RPATH),1)
LDFLAGS+=-Wl,-rpath "${LIBDIR}"
endif

OBJ+=${BIN}.o
BEXE=${BIN}${EXT_EXE}

ifeq ($(WITHNONPIC),1)
## LDFLAGS+=$(addsuffix /lib${BINDEPS}.a,$(addprefix ../../libr/,$(subst r_,,$(BINDEPS))))
LDFLAGS+=$(shell for a in ${BINDEPS} ; do b=`echo $$a |sed -e s,r_,,g`; echo ../../libr/$$b/lib$$a.${EXT_AR} ; done )
LDFLAGS+=../../shlr/sdb/src/libsdb.a
LDFLAGS+=../../shlr/grub/libgrubfs.a
LDFLAGS+=../../shlr/gdb/lib/libgdbr.a
LDFLAGS+=../../shlr/windbg/libr_windbg.a
LDFLAGS+=../../shlr/capstone/libcapstone.a
LDFLAGS+=../../shlr/java/libr_java.a
LDFLAGS+=../../libr/socket/libr_socket.a
LDFLAGS+=../../libr/util/libr_util.a
ifneq (${OSTYPE},haiku)
ifneq ($(CC),cccl)
LDFLAGS+=-lm
endif
endif
endif
LDFLAGS+=${DL_LIBS}
LDFLAGS+=${LINK}
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

# For some reason w32 builds contain -shared in LDFLAGS. boo!

ifneq ($(BIN)$(BINS),)

all: ${BEXE} ${BINS}

${BINS}: ${OBJS}
ifneq ($(SILENT),)
	@echo CC $@
endif
	${CC} ${CFLAGS} $@.c ${OBJS} ${REAL_LDFLAGS} -o $@

# -static fails because -ldl -lpthread static-gcc ...
${BEXE}: ${OBJ} ${SHARED_OBJ}
ifeq ($(WITHNONPIC),1)
	${CC} -pie ${CFLAGS} $+ -L.. -o $@ $(REAL_LDFLAGS)
else
ifneq ($(SILENT),)
	@echo LD $@
endif
	${CC} ${CFLAGS} $+ -L.. -o $@ $(REAL_LDFLAGS)
endif
endif

# Dummy myclean rule that can be overriden by the t/ Makefile
# TODO: move to config.mk ? it must be a precondition
myclean:

clean:: myclean
	-rm -f ${OBJS} ${OBJ} ${BEXE}

mrproper: clean
	-rm -f *.d

install:
	cd ../.. && ${MAKE} install

.PHONY: all clean myclean mrproper install
